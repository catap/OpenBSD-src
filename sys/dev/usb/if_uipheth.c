/*	$OpenBSD: $ */

/*
 * Copyright (c) 2024 Kirill A. Korinsky <kirill@korins.ky>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/device.h>
#include <sys/queue.h>

#include <machine/bus.h>

#include <net/if.h>
#include <net/if_media.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usbdi_util.h>
#include <dev/usb/usbdivar.h>
#include <dev/usb/usbdevs.h>

#include <dev/usb/mbim.h>

#include <dev/usb/if_uiphethreg.h>

#ifdef UIPHETH_DEBUG
#define DPRINTF(x)      do { printf x; } while (0)
#else
#define DPRINTF(x)
#endif

#define DEVNAME(sc)	((sc)->sc_dev.dv_xname)

#define GET_IFP(sc)	(&(sc)->sc_arpcom.ac_if)

int	uipheth_newbuf(struct uipheth_softc *, struct uipheth_chain *);

int	uipheth_ioctl(struct ifnet *, u_long, caddr_t);
void	uipheth_start(struct ifnet *);

void	uipheth_rxeof(struct usbd_xfer *, void *, usbd_status);
void	uipheth_txeof(struct usbd_xfer *, void *, usbd_status);
int	uipheth_rx_list_init(struct uipheth_softc *);
int	uipheth_tx_list_init(struct uipheth_softc *);

void	uipheth_init(struct uipheth_softc *);
void	uipheth_stop(struct uipheth_softc *);

int	uipheth_encap(struct uipheth_softc *, struct mbuf *, int);
void	uipheth_decap_ncm(struct uipheth_softc *, struct uipheth_chain *, u_int32_t);
void	uipheth_decap_legacy(struct uipheth_softc *, struct uipheth_chain *, u_int32_t);

int	uipheth_get_alt_idx(struct uipheth_softc *);
int	uipheth_get_mac(struct uipheth_softc *);
int	uipheth_enable_ncm(struct uipheth_softc *);
int	uipheth_check_carrier(struct uipheth_softc *);

void	uipheth_tick(void *);
void	uipheth_tick_task(void *);

int	uipheth_match(struct device *, void *, void *);
void	uipheth_attach(struct device *, struct device *, void *);
int	uipheth_detach(struct device *, int);


struct cfdriver uipheth_cd = {
	NULL, "uipheth", DV_IFNET
};

const struct cfattach uipheth_ca = {
	sizeof(struct uipheth_softc), uipheth_match, uipheth_attach, uipheth_detach
};


int
uipheth_newbuf(struct uipheth_softc *sc, struct uipheth_chain *c)
{
	struct mbuf *m_new = NULL;

	MGETHDR(m_new, M_DONTWAIT, MT_DATA);
	if (m_new == NULL) {
		printf("%s: no memory for rx list -- packet dropped!\n",
		    DEVNAME(sc));
		return (ENOBUFS);
	}
	MCLGET(m_new, M_DONTWAIT);
	if (!(m_new->m_flags & M_EXT)) {
		printf("%s: no memory for rx list -- packet dropped!\n",
		    DEVNAME(sc));
		m_freem(m_new);
		return (ENOBUFS);
	}
	m_new->m_len = m_new->m_pkthdr.len = MCLBYTES;

	m_adj(m_new, ETHER_ALIGN);
	c->sc_mbuf = m_new;
	return (0);
}

int
uipheth_ioctl(struct ifnet *ifp, u_long command, caddr_t data)
{
	struct uipheth_softc	*sc = ifp->if_softc;
	int			 s, error = 0;

	if (usbd_is_dying(sc->sc_udev))
		return ENXIO;

	s = splnet();

	switch(command) {
	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP;
		if (!(ifp->if_flags & IFF_RUNNING))
			uipheth_init(sc);
		break;

	case SIOCSIFFLAGS:
		if (ifp->if_flags & IFF_UP) {
			if (ifp->if_flags & IFF_RUNNING)
				error = ENETRESET;
			else
				uipheth_init(sc);
		} else {
			if (ifp->if_flags & IFF_RUNNING)
				uipheth_stop(sc);
		}
		break;

	default:
		error = ether_ioctl(ifp, &sc->sc_arpcom, command, data);
		break;
	}

	if (error == ENETRESET)
		error = 0;

	splx(s);
	return (error);
}

void
uipheth_start(struct ifnet *ifp)
{
	struct uipheth_softc	*sc;
	struct mbuf		*m_head = NULL;

	sc = ifp->if_softc;

	if (usbd_is_dying(sc->sc_udev) || ifq_is_oactive(&ifp->if_snd))
		return;

	m_head = ifq_dequeue(&ifp->if_snd);
	if (m_head == NULL)
		return;

	if (uipheth_encap(sc, m_head, 0)) {
		m_freem(m_head);
		ifp->if_oerrors++;
		ifq_set_oactive(&ifp->if_snd);
		return;
	}

#if NBPFILTER > 0
	if (ifp->if_bpf)
		bpf_mtap(ifp->if_bpf, m_head, BPF_DIRECTION_OUT);
#endif

	ifp->if_timer = 5;
	ifq_set_oactive(&ifp->if_snd);

	return;
}

void
uipheth_rxeof(struct usbd_xfer *xfer,
    void *priv,
    usbd_status status)
{
	struct uipheth_chain	*c;
	struct uipheth_softc	*sc;
	struct ifnet		*ifp;
	u_int32_t		 total_len;
	usbd_status		 err;

	c = priv;
	sc = c->sc_softc;
	ifp = GET_IFP(sc);
	total_len = 0;

	if (usbd_is_dying(sc->sc_udev) || !(ifp->if_flags & IFF_RUNNING))
		return;

	if (status != USBD_NORMAL_COMPLETION) {
		if (status == USBD_NOT_STARTED || status == USBD_CANCELLED)
			return;
		if (usbd_ratecheck(&sc->sc_rx_notice)) {
			DPRINTF(("%s: usb errors on rx: %s\n",
			    DEVNAME(sc), usbd_errstr(status)));
		}
		if (status == USBD_STALLED)
			usbd_clear_endpoint_stall_async(sc->sc_bulkrx_pipe);

		ifp->if_ierrors++;
		goto done;
	}

	usbd_get_xfer_status(xfer, NULL, NULL, &total_len, NULL);
	sc->sc_data.sc_decap(sc, c, total_len);

done:
	usbd_setup_xfer(c->sc_xfer, sc->sc_bulkrx_pipe, c, c->sc_buf,
	    sc->sc_data.sc_rx_bufsz, USBD_SHORT_XFER_OK | USBD_NO_COPY,
	    USBD_NO_TIMEOUT, uipheth_rxeof);
	err = usbd_transfer(c->sc_xfer);
	if (err && err != USBD_IN_PROGRESS) {
		printf("%s: failed to start rx fer: %s\n",
		    DEVNAME(sc), usbd_errstr(err));
		return;
	}
}

void
uipheth_txeof(struct usbd_xfer *xfer,
    void *priv,
    usbd_status status)
{
	struct uipheth_chain	*c;
	struct uipheth_softc	*sc;
	struct ifnet		*ifp;
	usbd_status		 err;
	int			 s;

	c = priv;
	sc = c->sc_softc;
	ifp = GET_IFP(sc);

	if (usbd_is_dying(sc->sc_udev))
		return;

	s = splnet();

	ifp->if_timer = 0;
	ifq_clr_oactive(&ifp->if_snd);

	if (status != USBD_NORMAL_COMPLETION) {
		if (status == USBD_NOT_STARTED || status == USBD_CANCELLED)
			goto done;

		ifp->if_oerrors++;
		DPRINTF(("%s: usb error on tx: %s\n", DEVNAME(sc),
		    usbd_errstr(status)));
		if (status == USBD_STALLED)
			usbd_clear_endpoint_stall_async(sc->sc_bulktx_pipe);

		goto done;
	}

	usbd_get_xfer_status(c->sc_xfer, NULL, NULL, NULL, &err);

	DPRINTF(("%s: sent on rx %d octets, status: %s\n",
	    DEVNAME(sc), xfer->actlen, usbd_errstr(err)));

	if (c->sc_mbuf != NULL) {
		m_freem(c->sc_mbuf);
		c->sc_mbuf = NULL;
	}

	if (err != USBD_NORMAL_COMPLETION)
		ifp->if_oerrors++;

	if (ifq_empty(&ifp->if_snd) == 0)
		uipheth_start(ifp);

done:
	splx(s);
}

int
uipheth_rx_list_init(struct uipheth_softc *sc)
{
	struct uipheth_cdata	*cd;
	struct uipheth_chain	*c;
	int			 i;

	cd = &sc->sc_data;
	for (i = 0; i < UIPHETH_RX_LIST_CNT; i++) {
		c = &cd->sc_rx_chain[i];
		c->sc_softc = sc;

		if (uipheth_newbuf(sc, c) == ENOBUFS)
			return (ENOBUFS);

		if (c->sc_xfer == NULL) {
			c->sc_xfer = usbd_alloc_xfer(sc->sc_udev);
			if (c->sc_xfer == NULL)
				return (ENOBUFS);
			c->sc_buf = usbd_alloc_buffer(c->sc_xfer,
			    sc->sc_data.sc_rx_bufsz);
			if (c->sc_buf == NULL)
				return (ENOBUFS);
		}
	}

	return (0);
}

int
uipheth_tx_list_init(struct uipheth_softc *sc)
{
	struct uipheth_cdata	*cd;
	struct uipheth_chain	*c;
	int			 i;

	cd = &sc->sc_data;
	for (i = 0; i < UIPHETH_TX_LIST_CNT; i++) {
		c = &cd->sc_tx_chain[i];
		c->sc_softc = sc;
		c->sc_mbuf = NULL;
		if (c->sc_xfer == NULL) {
			c->sc_xfer = usbd_alloc_xfer(sc->sc_udev);
			if (c->sc_xfer == NULL)
				return (ENOBUFS);
			c->sc_buf = usbd_alloc_buffer(c->sc_xfer,
			    UIPHETH_TX_BUFSZ);
			if (c->sc_buf == NULL)
				return (ENOBUFS);
		}
	}
	return (0);
}

void
uipheth_init(struct uipheth_softc *sc)
{
	struct ifnet		*ifp = GET_IFP(sc);
	int			 i, s;
	usbd_status		 err;

	/* TODO: peer with iphone */

	s = splnet();

	if (uipheth_tx_list_init(sc) == ENOBUFS) {
		printf("%s: tx list init failed\n",
		    DEVNAME(sc));
		splx(s);
		return;
	}

	if (uipheth_rx_list_init(sc) == ENOBUFS) {
		printf("%s: rx list init failed\n",
		    DEVNAME(sc));
		splx(s);
		return;
	}

	err = usbd_open_pipe(sc->sc_iface_data, sc->sc_bulkrx_no,
	    USBD_EXCLUSIVE_USE, &sc->sc_bulkrx_pipe);
	if (err) {
		printf("%s: open rx pipe failed: %s\n", DEVNAME(sc),
		    usbd_errstr(err));
		splx(s);
		return;
	}

	err = usbd_open_pipe(sc->sc_iface_data, sc->sc_bulktx_no,
	    USBD_EXCLUSIVE_USE, &sc->sc_bulktx_pipe);
	if (err) {
		printf("%s: open tx pipe failed: %s\n", DEVNAME(sc),
		    usbd_errstr(err));
		splx(s);
		return;
	}

	for (i = 0; i < UIPHETH_RX_LIST_CNT; i++) {
		struct uipheth_chain *c;

		c = &sc->sc_data.sc_rx_chain[i];
		usbd_setup_xfer(c->sc_xfer, sc->sc_bulkrx_pipe, c,
		    c->sc_buf, sc->sc_data.sc_rx_bufsz,
		    USBD_SHORT_XFER_OK | USBD_NO_COPY,
		    USBD_NO_TIMEOUT, uipheth_rxeof);
		err = usbd_transfer(c->sc_xfer);
		if (err && err != USBD_IN_PROGRESS) {
			printf("%s: failed to start rx fer: %s\n",
			    DEVNAME(sc), usbd_errstr(err));
			splx(s);
			return;
		}
	}

	ifp->if_flags |= IFF_RUNNING;
	ifq_clr_oactive(&ifp->if_snd);

	splx(s);
}

void
uipheth_stop(struct uipheth_softc *sc)
{
	usbd_status	 err;
	struct ifnet	*ifp;
	int		 i;

	ifp = GET_IFP(sc);
	ifp->if_timer = 0;
	ifp->if_flags &= ~IFF_RUNNING;
	ifq_clr_oactive(&ifp->if_snd);

	timeout_del(&sc->sc_tick_task_to);

	if (sc->sc_bulkrx_pipe != NULL) {
		err = usbd_close_pipe(sc->sc_bulkrx_pipe);
		if (err)
			printf("%s: close rx pipe failed: %s\n",
			    DEVNAME(sc), usbd_errstr(err));
		sc->sc_bulkrx_pipe = NULL;
	}

	if (sc->sc_bulktx_pipe != NULL) {
		err = usbd_close_pipe(sc->sc_bulktx_pipe);
		if (err)
			printf("%s: close tx pipe failed: %s\n",
			    DEVNAME(sc), usbd_errstr(err));
		sc->sc_bulktx_pipe = NULL;
	}

	for (i = 0; i < UIPHETH_RX_LIST_CNT; i++) {
		if (sc->sc_data.sc_rx_chain[i].sc_mbuf != NULL) {
			m_freem(sc->sc_data.sc_rx_chain[i].sc_mbuf);
			sc->sc_data.sc_rx_chain[i].sc_mbuf = NULL;
		}
		if (sc->sc_data.sc_rx_chain[i].sc_xfer != NULL) {
			usbd_free_xfer(sc->sc_data.sc_rx_chain[i].sc_xfer);
			sc->sc_data.sc_rx_chain[i].sc_xfer = NULL;
		}
	}

	for (i = 0; i < UIPHETH_TX_LIST_CNT; i++) {
		if (sc->sc_data.sc_tx_chain[i].sc_mbuf != NULL) {
			m_freem(sc->sc_data.sc_tx_chain[i].sc_mbuf);
			sc->sc_data.sc_tx_chain[i].sc_mbuf = NULL;
		}
		if (sc->sc_data.sc_tx_chain[i].sc_xfer != NULL) {
			usbd_free_xfer(sc->sc_data.sc_tx_chain[i].sc_xfer);
			sc->sc_data.sc_tx_chain[i].sc_xfer = NULL;
		}
	}
}

int
uipheth_encap(struct uipheth_softc *sc, struct mbuf *m, int idx)
{
	uint8_t				*buf;
	struct uipheth_chain		*c;
	usbd_status			 err;


	c = &sc->sc_data.sc_tx_chain[idx];

	if (m->m_pkthdr.len > ETHER_FRAME) {
		printf("%s: tbuf overflow: %u larger than %d\n",
		    DEVNAME(sc), m->m_pkthdr.len, ETHER_FRAME);
		m_adj(m, -(m->m_pkthdr.len - ETHER_FRAME));
	}

	buf = c->sc_buf + sc->sc_data.sc_tx_adj;

	if (sc->sc_data.sc_tx_adj)
		memset(c->sc_buf, 0, sc->sc_data.sc_tx_adj);

	m_copydata(m, 0, m->m_pkthdr.len, buf);

	if (m->m_pkthdr.len != ETHER_FRAME)
		memset(buf + m->m_pkthdr.len, 0,
		    ETHER_FRAME - m->m_pkthdr.len);

	c->sc_mbuf = m;

	usbd_setup_xfer(c->sc_xfer, sc->sc_bulktx_pipe, c, c->sc_buf,
	    UIPHETH_TX_BUFSZ, USBD_FORCE_SHORT_XFER | USBD_NO_COPY,
	    UIPHETH_TX_TIMEOUT, uipheth_txeof);

	err = usbd_transfer(c->sc_xfer);
	if (err != USBD_IN_PROGRESS) {
		printf("%s: failed to start rx fer: %s\n",
		    DEVNAME(sc), usbd_errstr(err));
		c->sc_mbuf = NULL;
		uipheth_stop(sc);
		return (EIO);
	}

	return (0);
}

int
uipheth_get_alt_idx(struct uipheth_softc *sc)
{
	usbd_status		err;
	usb_device_request_t	req;
	uint8_t			buf[UIPHETH_ALT_IDX_BUFSZ];

	req.bmRequestType = UT_READ_VENDOR_DEVICE;
	req.bRequest = UIPHETH_CMD_GET_ALT_IDX;
	USETW(req.wValue, 0);
	USETW(req.wIndex, sc->sc_ifaceno_ctl);
	USETW(req.wLength, ETHER_ADDR_LEN);
	err = usbd_do_request(sc->sc_udev, &req, buf);
	if (err != USBD_NORMAL_COMPLETION && err != USBD_SHORT_XFER) {
		printf("%s: unable to get alternative idx: %s\n",
		    DEVNAME(sc), usbd_errstr(err));
		return -1;
	}

	return (int) buf[0];
}

int
uipheth_get_mac(struct uipheth_softc *sc)
{
	usbd_status		err;
	usb_device_request_t	req;
	uint8_t			addr[ETHER_ADDR_LEN];

	req.bmRequestType = UT_READ_VENDOR_DEVICE;
	req.bRequest = UIPHETH_CMD_GET_MACADDR;
	USETW(req.wValue, 0);
	USETW(req.wIndex, sc->sc_ifaceno_ctl);
	USETW(req.wLength, ETHER_ADDR_LEN);
	err = usbd_do_request(sc->sc_udev, &req, addr);
	if (err != USBD_NORMAL_COMPLETION && err != USBD_SHORT_XFER) {
		printf("%s: unable to get hardware address: %s\n",
		    DEVNAME(sc), usbd_errstr(err));
		return -1;
	}

	bcopy(addr, sc->sc_arpcom.ac_enaddr, ETHER_ADDR_LEN);

	return 0;
}

int
uipheth_enable_ncm(struct uipheth_softc *sc)
{
	usb_device_request_t		 req;
	usbd_status			 err;

	req.bmRequestType = UT_WRITE_VENDOR_INTERFACE;
	req.bRequest = UIPHETH_CMD_ENABLE_NCM;
	USETW(req.wValue, 0);
	USETW(req.wIndex, sc->sc_ifaceno_ctl);
	USETW(req.wLength, 0);
	err = usbd_do_request(sc->sc_udev, &req, NULL);

	return (err == USBD_NORMAL_COMPLETION);
}

int
uipheth_update_carrier_on(struct uipheth_softc *sc)
{
	usb_device_request_t	 req;
	usbd_status		 err;
	uint8_t			 new_carrier_on;
	uint8_t			 buf[UIPHETH_CARRIER_BUFSZ];

	req.bmRequestType = UT_READ_VENDOR_DEVICE;
	req.bRequest = UIPHETH_CMD_CARRIER_CHK;
	USETW(req.wValue, 0);
	USETW(req.wIndex, sc->sc_ifaceno_ctl);
	USETW(req.wLength, UIPHETH_CARRIER_BUFSZ);

	err = usbd_do_request(sc->sc_udev, &req, buf);
	if (err != USBD_NORMAL_COMPLETION) {
		printf("%s: unable to get carrier status: %s\n",
		    DEVNAME(sc), usbd_errstr(err));
		return -1;
	}

	new_carrier_on = (buf[0] == UIPHETH_CARRIER_ON);

#ifdef UIPHETH_DEBUG
	if (sc->sc_carrier_on != new_carrier_on)
		DPRINTF(("%s: change carrier status: %d -> %d\n",
		    DEVNAME(sc), sc->sc_carrier_on, new_carrier_on));
#endif

	sc->sc_carrier_on = new_carrier_on;

	return 0;
}

void
uipheth_tick(void *xsc)
{
	struct uipheth_softc	*sc = xsc;

	if (sc == NULL)
		return;

	usb_add_task(sc->sc_udev, &sc->sc_tick_task);
}

void
uipheth_tick_task(void *xsc)
{
	struct uipheth_softc	*sc = xsc;

	if (sc == NULL)
		return;

	if (usbd_is_dying(sc->sc_udev))
		return;

	if (uipheth_update_carrier_on(sc))
		return;

	timeout_add_msec(&sc->sc_tick_task_to, UIPHETH_TICK_TASK_INT);
}

void
uipheth_decap_ncm(struct uipheth_softc *sc, struct uipheth_chain *c, u_int32_t len)
{
	struct mbuf			*m;
	struct mbuf_list		 ml = MBUF_LIST_INITIALIZER();
	struct ifnet			*ifp;
	uint8_t				*buf;
	int			 	 s, blen;
	int	 			 ptrlen, ptroff, dgentryoff;
	uint32_t                         doff, dlen;
	struct ncm_header16 		*ncmh;
	struct ncm_pointer16		*ncm0;
	struct ncm_pointer16_dgram	*dpe;

	DPRINTF(("%s: read %d octets\n", DEVNAME(sc), len));

	ifp = GET_IFP(sc);

	if (len < UIPHETH_NCM_HEADER_SIZE) {
		ifp->if_ierrors++;
		return;
	}

	ncmh = (struct ncm_header16 *)c->sc_buf;
	if (UGETDW(ncmh->dwSignature) != NCM_HDR16_SIG) {
		DPRINTF(("%s: unsupported NCM header signature"
		    " (0x%08x)\n",
		    DEVNAME(sc), UGETDW(ncmh->dwSignature)));
		ifp->if_ierrors++;
		return;
	}
	blen = UGETW(ncmh->wBlockLength);
	ptroff = UGETW(ncmh->wNdpIndex);
	if (UGETDW(ncmh->wHeaderLength) != sizeof(*ncmh)) {
		DPRINTF(("%s: bad header len %d for NTH16"
		    " (exp %zu)\n",
		    DEVNAME(sc), UGETW(ncmh->wHeaderLength),
		    sizeof (*ncmh)));
		ifp->if_ierrors++;
		return;
	}

	if (blen != 0 && len < blen) {
		DPRINTF(("%s: bad NTB len (%d) for %d bytes"
		    " of data\n",
		    DEVNAME(sc), blen, len));
		ifp->if_ierrors++;
		return;
	}

	ncm0 = (struct ncm_pointer16 *)(c->sc_buf + ptroff);
	ptrlen = UGETW(ncm0->wLength);
	if (len < ptrlen + ptroff) {
		DPRINTF(("%s: packet too small (%d)\n",
		    DEVNAME(sc), len));
		ifp->if_ierrors++;
		return;
	}

	if (!MBIM_NCM_NTH16_ISISG(UGETDW(ncm0->dwSignature))) {
		DPRINTF(("%s: unsupported NCM pointer signature"
		    " (0x%08x)\n",
		    DEVNAME(sc), UGETDW(ncm0->dwSignature)));
		ifp->if_ierrors++;
		return;
	}

	dgentryoff = offsetof(struct ncm_pointer16, dgram);

	while (dgentryoff < ptrlen) {
		if (ptroff + dgentryoff < sizeof (*dpe))
			break;
		dpe = (struct ncm_pointer16_dgram *)
		    (c->sc_buf + ptroff + dgentryoff);
		dgentryoff += sizeof (*dpe);
		dlen = UGETW(dpe->wDatagramLen);
		doff = UGETW(dpe->wDatagramIndex);

		/* zero entry, stop looping */
		if (dlen == 0 || doff == 0)
			break;

		if (len < dlen + doff) {
			DPRINTF(("%s: datagram too large"
			    " (%d @ off %d)\n",
			    DEVNAME(sc), dlen, doff));
			continue;
		}

		buf = c->sc_buf + doff;
		DPRINTF(("%s: decap %d bytes\n",
		    DEVNAME(sc), dlen));

		m = c->sc_mbuf;

		memcpy(mtod(m, uint8_t *), buf, dlen);

		m->m_pkthdr.len = m->m_len = dlen ;

		if (uipheth_newbuf(sc, c) == ENOBUFS)
			ifp->if_ierrors++;
		else
			ml_enqueue(&ml, m);
	}

	if (ml_empty(&ml))
		return;

	s = splnet();
	if_input(ifp, &ml);
	splx(s);
}

void
uipheth_decap_legacy(struct uipheth_softc *sc, struct uipheth_chain *c, u_int32_t len)
{
	struct mbuf			*m;
	struct mbuf_list		 ml = MBUF_LIST_INITIALIZER();
	struct ifnet			*ifp;
	uint8_t				*buf;
	int			 	 s;

	DPRINTF(("%s: read %d octets\n", DEVNAME(sc), len));

	ifp = GET_IFP(sc);

	if (len < UIPHETH_RX_ADJ) {
		ifp->if_ierrors++;
		return;
	}

	buf = c->sc_buf + UIPHETH_RX_ADJ;
	len -= UIPHETH_RX_ADJ;

	m = c->sc_mbuf;

	memcpy(mtod(m, uint8_t *), buf, len);

	m->m_pkthdr.len = m->m_len = len - UIPHETH_RX_ADJ;

	if (uipheth_newbuf(sc, c) == ENOBUFS)
		ifp->if_ierrors++;
	else
		ml_enqueue(&ml, m);

	if (ml_empty(&ml))
		return;

	s = splnet();
	if_input(ifp, &ml);
	splx(s);
}

int
uipheth_match(struct device *parent, void *match, void *aux)
{
	struct usb_attach_arg 		*uaa = aux;
	usb_interface_descriptor_t	*id;
	usb_device_descriptor_t		*dd;

	if (uaa->vendor != USB_VENDOR_APPLE)
		return UMATCH_NONE;

	if (uaa->iface == NULL)
		return UMATCH_NONE;

	id = usbd_get_interface_descriptor(uaa->iface);
	dd = usbd_get_device_descriptor(uaa->device);
	if (id == NULL || dd == NULL)
		return UMATCH_NONE;

	if (UGETW(dd->idVendor) == USB_VENDOR_APPLE &&
	    id->bInterfaceClass == UICLASS_VENDOR &&
	    id->bInterfaceSubClass == UIPHETH_USBINTF_SUBCLASS &&
	    id->bInterfaceProtocol == UIPHETH_USBINTF_PROTOCOL)
		return UMATCH_VENDOR_IFACESUBCLASS_IFACEPROTO;

	return UMATCH_NONE;
}

void
uipheth_attach(struct device *parent, struct device *self, void *aux)
{
	int				 i, s;
	int				 use_ncm, alt_idx, rx_no, tx_no;
	struct uipheth_softc		*sc;
	struct usb_attach_arg		*uaa;
	struct ifnet			*ifp;
	usb_interface_descriptor_t	*id;
	usb_endpoint_descriptor_t	*ed;

	sc = (void *)self;
	uaa = aux;

	sc->sc_attached = 0;
	sc->sc_udev = uaa->device;

	usb_init_task(&sc->sc_tick_task, uipheth_tick_task, sc,
	    USB_TASK_TYPE_GENERIC);

	id = usbd_get_interface_descriptor(uaa->iface);
	sc->sc_ifaceno_ctl = id->bInterfaceNumber;

	DPRINTF(("%s: using %d as control iface\n",
	    DEVNAME(sc), sc->sc_ifaceno_ctl));

	/* Can't get Alt Interface, degradate to linux way */
	if ((alt_idx = uipheth_get_alt_idx(sc)) < 0) {
		alt_idx = UIPHETH_ALT_INTFNUM;
		sc->sc_data.sc_tx_adj = 0;
	} else {
		sc->sc_data.sc_tx_adj = UIPHETH_TX_ADJ;
	}

	DPRINTF(("%s: using %d as alt interface, adj: %d\n",
	    DEVNAME(sc), alt_idx, sc->sc_data.sc_tx_adj));

	sc->sc_iface_data = uaa->ifaces[alt_idx];
	usbd_claim_iface(sc->sc_udev, alt_idx);

	if (usbd_set_interface(uaa->iface, alt_idx)) {
		printf("%s: could not switch to alt interface: %d\n",
			DEVNAME(sc), alt_idx);
		goto fail;
	}

	id = usbd_get_interface_descriptor(sc->sc_iface_data);
	if (id == NULL) {
		printf("%s: no data interface descriptor\n",
		       DEVNAME(sc));
		goto fail;
	}

	rx_no = tx_no = -1;
	for (i = 0; i < id->bNumEndpoints; i++) {
		ed = usbd_interface2endpoint_descriptor(
		    sc->sc_iface_data, i);
		if (!ed) {
			printf("%s: no descriptor for bulk endpoint %u\n",
			    DEVNAME(sc), i);
			goto fail;
		}

		DPRINTF(("%s: checking endpoint %d / %d, DIR: %d, TYPE: %d \n",
		    DEVNAME(sc), i, ed->bEndpointAddress,
		    UE_GET_DIR(ed->bEndpointAddress),
		    UE_GET_XFERTYPE(ed->bmAttributes)));

		if (UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_IN &&
		    UE_GET_XFERTYPE(ed->bmAttributes) == UE_BULK) {
			rx_no = ed->bEndpointAddress;
		} else if (
		    UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_OUT &&
		    UE_GET_XFERTYPE(ed->bmAttributes) == UE_BULK) {
			tx_no = ed->bEndpointAddress;
		}
	}

	if (rx_no == -1) {
		printf("%s: could not find data bulk in\n",
		       DEVNAME(sc));
		goto fail;
	}
	if (tx_no == -1 ) {
		printf("%s: could not find data bulk out\n",
		       DEVNAME(sc));
		goto fail;
	}

	sc->sc_bulkrx_no = rx_no;
	sc->sc_bulktx_no = tx_no;

	DPRINTF(("%s: using %d as RX, and %d TX out\n",
	    DEVNAME(sc), sc->sc_bulkrx_no, sc->sc_bulktx_no));

	ifp = GET_IFP(sc);
	ifp->if_softc = sc;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_start = uipheth_start;
	ifp->if_ioctl = uipheth_ioctl;

	strlcpy(ifp->if_xname, DEVNAME(sc), IFNAMSIZ);

	if (uipheth_get_mac(sc))
	    goto fail;

	DPRINTF(("%s: attaching devices with address %s\n",
	    DEVNAME(sc), ether_sprintf(sc->sc_arpcom.ac_enaddr)));

	/* once enabled, it needs to reboot the phone to be disabled  */
	use_ncm = uipheth_enable_ncm(sc);

	DPRINTF(("%s: use NCM: %d\n", DEVNAME(sc), use_ncm));

	/* use NCM as a way to determine legacy protocol */
	if (use_ncm) {
		sc->sc_data.sc_rx_bufsz = UIPHETH_RX_BUFSZ_LEGACY;
		sc->sc_data.sc_decap = uipheth_decap_legacy;
	} else {
		sc->sc_data.sc_rx_bufsz = UIPHETH_RX_BUFSZ_NCM;
		sc->sc_data.sc_decap = uipheth_decap_ncm;
	}

	s = splnet();

	if_attach(ifp);
	ether_ifattach(ifp);

	sc->sc_attached = 1;

	splx(s);

	timeout_set(&sc->sc_tick_task_to, uipheth_tick, sc);
	timeout_add_msec(&sc->sc_tick_task_to, UIPHETH_TICK_TASK_INT);

	return;

fail:
	usbd_deactivate(sc->sc_udev);
}

int
uipheth_detach(struct device *self, int flags)
{
	struct uipheth_softc	*sc;
	struct ifnet		*ifp;
	int			 s;

	sc = (void *)self;

	DPRINTF(("%s: detach, flags %u\n", DEVNAME(sc), flags));

	if (!sc->sc_attached)
		return 0;

	if (timeout_initialized(&sc->sc_tick_task_to))
		timeout_del(&sc->sc_tick_task_to);

	usb_rem_task(sc->sc_udev, &sc->sc_tick_task);

	s = splnet();

	ifp = GET_IFP(sc);

	if (ifp->if_softc != NULL) {
		ether_ifdetach(ifp);
		if_detach(ifp);
	}

	uipheth_stop(sc);

	sc->sc_attached = 0;

	splx(s);

	return 0;
}
