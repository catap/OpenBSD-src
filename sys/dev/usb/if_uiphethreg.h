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

#define UIPHETH_USBINTF_SUBCLASS	0xfd
#define UIPHETH_USBINTF_PROTOCOL	1

#define UIPHETH_RX_LIST_CNT	1
#define UIPHETH_TX_LIST_CNT	1

#define ETHER_FRAME		(ETHER_MAX_LEN - ETHER_CRC_LEN)

#define UIPHETH_TX_ADJ		2	/* padding at front of frame */
#define UIPHETH_TX_BUFSZ		(UIPHETH_TX_ADJ + ETHER_FRAME)
#define UIPHETH_TX_TIMEOUT	5000	/* ms */

#define UIPHETH_NCM_HEADER_SIZE	108	/* NCMH + NCM0 */
#define UIPHETH_RX_ADJ		2	/* padding at front of frame */
#define UIPHETH_RX_BUFSZ_LEGACY	(UIPHETH_RX_ADJ + ETHER_FRAME)
#define UIPHETH_RX_BUFSZ_NCM	65536

#define UIPHETH_ALT_INTFNUM      1

#define UIPHETH_CMD_GET_MACADDR	0x00
#define UIPHETH_CMD_GET_ALT_IDX	0x03
#define UIPHETH_CMD_ENABLE_NCM	0x04
#define UIPHETH_CMD_CARRIER_CHK	0x45

#define UIPHETH_ALT_IDX_BUFSZ	4

#define UIPHETH_CARRIER_ON	0x04
#define UIPHETH_CARRIER_BUFSZ	3

#define UIPHETH_TICK_TASK_INT	1000	/* ms */

struct uipheth_chain {
	struct uipheth_softc	*sc_softc;
	struct usbd_xfer	*sc_xfer;
	uint8_t			*sc_buf;
	struct mbuf		*sc_mbuf;
};

struct uipheth_cdata {
	struct uipheth_chain	 sc_rx_chain[UIPHETH_RX_LIST_CNT];
	struct uipheth_chain	 sc_tx_chain[UIPHETH_TX_LIST_CNT];

	uint32_t		 sc_tx_adj;

	uint32_t		 sc_rx_bufsz;

	void (*sc_decap)(struct uipheth_softc *, struct uipheth_chain *, u_int32_t);
};

struct uipheth_softc {
	struct device		 sc_dev;

	uint8_t			 sc_attached;
	struct arpcom		 sc_arpcom;

	struct usbd_device	*sc_udev;
	uint8_t			 sc_ifaceno_ctl;
	struct usbd_interface	*sc_iface_data;

	struct timeval		 sc_rx_notice;
	uint8_t			 sc_bulkrx_no;
	struct usbd_pipe	*sc_bulkrx_pipe;
	uint8_t			 sc_bulktx_no;
	struct usbd_pipe	*sc_bulktx_pipe;

	struct usb_task		 sc_tick_task;
	struct timeout		 sc_tick_task_to;

	uint8_t			 sc_carrier_on;

	struct uipheth_cdata	 sc_data;
};
