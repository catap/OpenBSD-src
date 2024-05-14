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

/* TODO: disable debug by default */
#define IPHETH_DEBUG

#ifdef IPHETH_DEBUG
#define DPRINTF(x)      do { printf x; } while (0)
#else
#define DPRINTF(x)
#endif

#define	IPHETH_USBINTF_SUBCLASS	0xfd
#define	IPHETH_USBINTF_PROTOCOL	1

#define DEVNAME(sc)	((sc)->sc_dev.dv_xname)

#define GET_IFP(sc)	(&(sc)->sc_arpcom.ac_if)
struct ipheth_softc {
	struct device			sc_dev;

	char				sc_attached;
	struct arpcom			sc_arpcom;

	struct usbd_device		*sc_udev;
	int				sc_ifaceno_ctl;
	struct usbd_interface		*sc_iface_data;

	struct timeval			sc_rx_notice;
	int				sc_bulkin_no;
	struct usbd_pipe		*sc_bulkin_pipe;
	int				sc_bulkout_no;
	struct usbd_pipe		*sc_bulkout_pipe;
};


int	ipheth_match(struct device *, void *, void *);
void	ipheth_attach(struct device *, struct device *, void *);
int	ipheth_detach(struct device *, int);


struct cfdriver ipheth_cd = {
	NULL, "ipheth", DV_IFNET
};

const struct cfattach ipheth_ca = {
	sizeof(struct ipheth_softc), ipheth_match, ipheth_attach, ipheth_detach
};


int
ipheth_match(struct device *parent, void *match, void *aux)
{
	struct usb_attach_arg 		*uaa = aux;
	usb_interface_descriptor_t	*id;

	if (uaa->iface == NULL || uaa->configno != 1)
		return UMATCH_NONE;

	if (uaa->vendor != USB_VENDOR_APPLE)
		return UMATCH_NONE;

	DPRINTF(("ipheth_match: nifaces: %d\n", uaa->nifaces));

	id = usbd_get_interface_descriptor(uaa->iface);
	if (id == NULL)
		return UMATCH_NONE;

	DPRINTF(("ipheth_match: class: %d, subClass: %d, Protocol: %d\n",
		id->bInterfaceClass, id->bInterfaceSubClass,
		id->bInterfaceProtocol));

	/* my iPhone annoucnes only as UICLASS_IMAGE / 1 / 1 */
	if (id->bInterfaceClass != UICLASS_VENDOR)
		return UMATCH_NONE;

	if (id->bInterfaceSubClass != IPHETH_USBINTF_SUBCLASS)
		return UMATCH_NONE;

	if (id->bInterfaceProtocol != IPHETH_USBINTF_PROTOCOL)
		return UMATCH_NONE;

	return UMATCH_VENDOR_PRODUCT;
}

void
ipheth_attach(struct device *parent, struct device *self, void *aux)
{
	struct ipheth_softc		*sc;
	struct usb_attach_arg		*uaa;
	struct ifnet			*ifp;
	usb_interface_descriptor_t	*id;
	int				s;

	sc = (void *)self;
	uaa = aux;

	sc->sc_attached = 0;
	sc->sc_udev = uaa->device;
	id = usbd_get_interface_descriptor(uaa->iface);
	sc->sc_ifaceno_ctl = id->bInterfaceNumber;

	sc->sc_iface_data = uaa->ifaces[0];
	usbd_claim_iface(sc->sc_udev, 0);

	if (usbd_set_interface(uaa->iface, 1)) {
		printf("%s: could not switch to Alt Interface 1\n",
			DEVNAME(sc));
		return;
	}

	usbd_claim_iface(sc->sc_udev, 1);

	ifp = GET_IFP(sc);
	ifp->if_softc = sc;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	/* ifp->if_start = ipheth_start; */
	/* ifp->if_ioctl = ipheth_ioctl; */
	/* ifp->if_watchdog = ipheth_watchdog; */


	strlcpy(ifp->if_xname, DEVNAME(sc), IFNAMSIZ);

	DPRINTF(("ipheth_attach: %s\n", DEVNAME(sc)));

	s = splnet();

	sc->sc_attached = 1;

	splx(s);
}

int
ipheth_detach(struct device *self, int flags)
{
	struct ipheth_softc	*sc;
	int			s;

	sc = (void*)self;

	DPRINTF(("ipheth_detach: %s flags %u\n", DEVNAME(sc), flags));

	if (!sc->sc_attached)
		return 0;

	s = splnet();

	sc->sc_attached = 0;

	splx(s);

	return 0;
}
