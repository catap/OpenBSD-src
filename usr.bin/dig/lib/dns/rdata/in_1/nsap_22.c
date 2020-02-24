/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: nsap_22.c,v 1.5 2020/02/24 12:06:51 florian Exp $ */

/* Reviewed: Fri Mar 17 10:41:07 PST 2000 by gson */

/* RFC1706 */

#ifndef RDATA_IN_1_NSAP_22_C
#define RDATA_IN_1_NSAP_22_C

#define RRTYPE_NSAP_ATTRIBUTES (0)

static inline isc_result_t
totext_in_nsap(ARGS_TOTEXT) {
	isc_region_t region;
	char buf[sizeof("xx")];

	REQUIRE(rdata->type == dns_rdatatype_nsap);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->length != 0);

	UNUSED(tctx);

	dns_rdata_toregion(rdata, &region);
	RETERR(str_totext("0x", target));
	while (region.length != 0) {
		snprintf(buf, sizeof(buf), "%02x", region.base[0]);
		isc_region_consume(&region, 1);
		RETERR(str_totext(buf, target));
	}
	return (ISC_R_SUCCESS);
}

static inline isc_result_t
fromwire_in_nsap(ARGS_FROMWIRE) {
	isc_region_t region;

	REQUIRE(type == dns_rdatatype_nsap);
	REQUIRE(rdclass == dns_rdataclass_in);

	UNUSED(type);
	UNUSED(dctx);
	UNUSED(options);
	UNUSED(rdclass);

	isc_buffer_activeregion(source, &region);
	if (region.length < 1)
		return (ISC_R_UNEXPECTEDEND);

	RETERR(mem_tobuffer(target, region.base, region.length));
	isc_buffer_forward(source, region.length);
	return (ISC_R_SUCCESS);
}

static inline isc_result_t
towire_in_nsap(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_nsap);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	return (mem_tobuffer(target, rdata->data, rdata->length));
}


static inline isc_result_t
fromstruct_in_nsap(ARGS_FROMSTRUCT) {
	dns_rdata_in_nsap_t *nsap = source;

	REQUIRE(type == dns_rdatatype_nsap);
	REQUIRE(rdclass == dns_rdataclass_in);
	REQUIRE(source != NULL);
	REQUIRE(nsap->common.rdtype == type);
	REQUIRE(nsap->common.rdclass == rdclass);
	REQUIRE(nsap->nsap != NULL || nsap->nsap_len == 0);

	UNUSED(type);
	UNUSED(rdclass);

	return (mem_tobuffer(target, nsap->nsap, nsap->nsap_len));
}

static inline isc_result_t
tostruct_in_nsap(ARGS_TOSTRUCT) {
	dns_rdata_in_nsap_t *nsap = target;
	isc_region_t r;

	REQUIRE(rdata->type == dns_rdatatype_nsap);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(target != NULL);
	REQUIRE(rdata->length != 0);

	nsap->common.rdclass = rdata->rdclass;
	nsap->common.rdtype = rdata->type;
	ISC_LINK_INIT(&nsap->common, link);

	dns_rdata_toregion(rdata, &r);
	nsap->nsap_len = r.length;
	nsap->nsap = mem_maybedup(r.base, r.length);
	if (nsap->nsap == NULL)
		return (ISC_R_NOMEMORY);

	return (ISC_R_SUCCESS);
}

static inline void
freestruct_in_nsap(ARGS_FREESTRUCT) {
	dns_rdata_in_nsap_t *nsap = source;

	REQUIRE(source != NULL);
	REQUIRE(nsap->common.rdclass == dns_rdataclass_in);
	REQUIRE(nsap->common.rdtype == dns_rdatatype_nsap);

	if (nsap->nsap != NULL)
		free(nsap->nsap);
}



#endif	/* RDATA_IN_1_NSAP_22_C */
