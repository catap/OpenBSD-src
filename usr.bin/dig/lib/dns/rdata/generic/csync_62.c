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

/* RFC 7477 */

#ifndef RDATA_GENERIC_CSYNC_62_C
#define RDATA_GENERIC_CSYNC_62_C

#define RRTYPE_CSYNC_ATTRIBUTES 0

static inline isc_result_t
totext_csync(ARGS_TOTEXT) {
	unsigned long num;
	char buf[sizeof("0123456789")];	/* Also TYPE65535 */
	isc_region_t sr;

	REQUIRE(rdata->type == dns_rdatatype_csync);
	REQUIRE(rdata->length >= 6);

	UNUSED(tctx);

	dns_rdata_toregion(rdata, &sr);

	num = uint32_fromregion(&sr);
	isc_region_consume(&sr, 4);
	snprintf(buf, sizeof(buf), "%lu", num);
	RETERR(str_totext(buf, target));

	RETERR(str_totext(" ", target));

	num = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	snprintf(buf, sizeof(buf), "%lu", num);
	RETERR(str_totext(buf, target));

	/*
	 * Don't leave a trailing space when there's no typemap present.
	 */
	if (sr.length > 0) {
		RETERR(str_totext(" ", target));
	}
	return (typemap_totext(&sr, NULL, target));
}

static /* inline */ isc_result_t
fromwire_csync(ARGS_FROMWIRE) {
	isc_region_t sr;

	REQUIRE(type == dns_rdatatype_csync);

	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(options);
	UNUSED(dctx);

	/*
	 * Serial + Flags
	 */
	isc_buffer_activeregion(source, &sr);
	if (sr.length < 6)
		return (ISC_R_UNEXPECTEDEND);

	RETERR(mem_tobuffer(target, sr.base, 6));
	isc_buffer_forward(source, 6);
	isc_region_consume(&sr, 6);

	RETERR(typemap_test(&sr, ISC_TRUE));

	RETERR(mem_tobuffer(target, sr.base, sr.length));
	isc_buffer_forward(source, sr.length);
	return (ISC_R_SUCCESS);
}

static inline isc_result_t
towire_csync(ARGS_TOWIRE) {

	REQUIRE(rdata->type == dns_rdatatype_csync);
	REQUIRE(rdata->length >= 6);

	UNUSED(cctx);

	return (mem_tobuffer(target, rdata->data, rdata->length));
}


static inline isc_result_t
fromstruct_csync(ARGS_FROMSTRUCT) {
	dns_rdata_csync_t *csync = source;
	isc_region_t region;

	REQUIRE(type == dns_rdatatype_csync);
	REQUIRE(source != NULL);
	REQUIRE(csync->common.rdtype == type);
	REQUIRE(csync->common.rdclass == rdclass);
	REQUIRE(csync->typebits != NULL || csync->len == 0);

	UNUSED(type);
	UNUSED(rdclass);

	RETERR(uint32_tobuffer(csync->serial, target));
	RETERR(uint16_tobuffer(csync->flags, target));

	region.base = csync->typebits;
	region.length = csync->len;
	RETERR(typemap_test(&region, ISC_TRUE));
	return (mem_tobuffer(target, csync->typebits, csync->len));
}

static inline isc_result_t
tostruct_csync(ARGS_TOSTRUCT) {
	isc_region_t region;
	dns_rdata_csync_t *csync = target;

	REQUIRE(rdata->type == dns_rdatatype_csync);
	REQUIRE(target != NULL);
	REQUIRE(rdata->length != 0);

	csync->common.rdclass = rdata->rdclass;
	csync->common.rdtype = rdata->type;
	ISC_LINK_INIT(&csync->common, link);

	dns_rdata_toregion(rdata, &region);

	csync->serial = uint32_fromregion(&region);
	isc_region_consume(&region, 4);

	csync->flags = uint16_fromregion(&region);
	isc_region_consume(&region, 2);

	csync->len = region.length;
	csync->typebits = mem_maybedup(region.base, region.length);
	if (csync->typebits == NULL)
		goto cleanup;

	return (ISC_R_SUCCESS);

 cleanup:
	return (ISC_R_NOMEMORY);
}

static inline void
freestruct_csync(ARGS_FREESTRUCT) {
	dns_rdata_csync_t *csync = source;

	REQUIRE(source != NULL);
	REQUIRE(csync->common.rdtype == dns_rdatatype_csync);

	free(csync->typebits);
}


#endif	/* RDATA_GENERIC_CSYNC_62_C */
