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

/* $Id: hinfo_13.c,v 1.5 2020/02/24 12:06:51 florian Exp $ */

/*
 * Reviewed: Wed Mar 15 16:47:10 PST 2000 by halley.
 */

#ifndef RDATA_GENERIC_HINFO_13_C
#define RDATA_GENERIC_HINFO_13_C

#define RRTYPE_HINFO_ATTRIBUTES (0)

static inline isc_result_t
totext_hinfo(ARGS_TOTEXT) {
	isc_region_t region;

	UNUSED(tctx);

	REQUIRE(rdata->type == dns_rdatatype_hinfo);
	REQUIRE(rdata->length != 0);

	dns_rdata_toregion(rdata, &region);
	RETERR(txt_totext(&region, ISC_TRUE, target));
	RETERR(str_totext(" ", target));
	return (txt_totext(&region, ISC_TRUE, target));
}

static inline isc_result_t
fromwire_hinfo(ARGS_FROMWIRE) {

	REQUIRE(type == dns_rdatatype_hinfo);

	UNUSED(type);
	UNUSED(dctx);
	UNUSED(rdclass);
	UNUSED(options);

	RETERR(txt_fromwire(source, target));
	return (txt_fromwire(source, target));
}

static inline isc_result_t
towire_hinfo(ARGS_TOWIRE) {

	UNUSED(cctx);

	REQUIRE(rdata->type == dns_rdatatype_hinfo);
	REQUIRE(rdata->length != 0);

	return (mem_tobuffer(target, rdata->data, rdata->length));
}


static inline isc_result_t
fromstruct_hinfo(ARGS_FROMSTRUCT) {
	dns_rdata_hinfo_t *hinfo = source;

	REQUIRE(type == dns_rdatatype_hinfo);
	REQUIRE(source != NULL);
	REQUIRE(hinfo->common.rdtype == type);
	REQUIRE(hinfo->common.rdclass == rdclass);

	UNUSED(type);
	UNUSED(rdclass);

	RETERR(uint8_tobuffer(hinfo->cpu_len, target));
	RETERR(mem_tobuffer(target, hinfo->cpu, hinfo->cpu_len));
	RETERR(uint8_tobuffer(hinfo->os_len, target));
	return (mem_tobuffer(target, hinfo->os, hinfo->os_len));
}

static inline isc_result_t
tostruct_hinfo(ARGS_TOSTRUCT) {
	dns_rdata_hinfo_t *hinfo = target;
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_hinfo);
	REQUIRE(target != NULL);
	REQUIRE(rdata->length != 0);

	hinfo->common.rdclass = rdata->rdclass;
	hinfo->common.rdtype = rdata->type;
	ISC_LINK_INIT(&hinfo->common, link);

	dns_rdata_toregion(rdata, &region);
	hinfo->cpu_len = uint8_fromregion(&region);
	isc_region_consume(&region, 1);
	hinfo->cpu = mem_maybedup(region.base, hinfo->cpu_len);
	if (hinfo->cpu == NULL)
		return (ISC_R_NOMEMORY);
	isc_region_consume(&region, hinfo->cpu_len);

	hinfo->os_len = uint8_fromregion(&region);
	isc_region_consume(&region, 1);
	hinfo->os = mem_maybedup(region.base, hinfo->os_len);
	if (hinfo->os == NULL)
		goto cleanup;

	return (ISC_R_SUCCESS);

 cleanup:
	free(hinfo->cpu);
	return (ISC_R_NOMEMORY);
}

static inline void
freestruct_hinfo(ARGS_FREESTRUCT) {
	dns_rdata_hinfo_t *hinfo = source;

	REQUIRE(source != NULL);

	free(hinfo->cpu);
	free(hinfo->os);
}


#endif	/* RDATA_GENERIC_HINFO_13_C */
