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

/* $Id: mf_4.c,v 1.5 2020/02/24 12:06:51 florian Exp $ */

/* reviewed: Wed Mar 15 17:47:33 PST 2000 by brister */

#ifndef RDATA_GENERIC_MF_4_C
#define RDATA_GENERIC_MF_4_C

#define RRTYPE_MF_ATTRIBUTES (0)

static inline isc_result_t
totext_mf(ARGS_TOTEXT) {
	isc_region_t region;
	dns_name_t name;
	dns_name_t prefix;
	isc_boolean_t sub;

	REQUIRE(rdata->type == dns_rdatatype_mf);
	REQUIRE(rdata->length != 0);

	dns_name_init(&name, NULL);
	dns_name_init(&prefix, NULL);

	dns_rdata_toregion(rdata, &region);
	dns_name_fromregion(&name, &region);

	sub = name_prefix(&name, tctx->origin, &prefix);

	return (dns_name_totext(&prefix, sub, target));
}

static inline isc_result_t
fromwire_mf(ARGS_FROMWIRE) {
	dns_name_t name;

	REQUIRE(type == dns_rdatatype_mf);

	UNUSED(type);
	UNUSED(rdclass);

	dns_decompress_setmethods(dctx, DNS_COMPRESS_GLOBAL14);

	dns_name_init(&name, NULL);
	return (dns_name_fromwire(&name, source, dctx, options, target));
}

static inline isc_result_t
towire_mf(ARGS_TOWIRE) {
	dns_name_t name;
	dns_offsets_t offsets;
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_mf);
	REQUIRE(rdata->length != 0);

	dns_compress_setmethods(cctx, DNS_COMPRESS_GLOBAL14);

	dns_name_init(&name, offsets);
	dns_rdata_toregion(rdata, &region);
	dns_name_fromregion(&name, &region);

	return (dns_name_towire(&name, cctx, target));
}


static inline isc_result_t
fromstruct_mf(ARGS_FROMSTRUCT) {
	dns_rdata_mf_t *mf = source;
	isc_region_t region;

	REQUIRE(type == dns_rdatatype_mf);
	REQUIRE(source != NULL);
	REQUIRE(mf->common.rdtype == type);
	REQUIRE(mf->common.rdclass == rdclass);

	UNUSED(type);
	UNUSED(rdclass);

	dns_name_toregion(&mf->mf, &region);
	return (isc_buffer_copyregion(target, &region));
}

static inline isc_result_t
tostruct_mf(ARGS_TOSTRUCT) {
	dns_rdata_mf_t *mf = target;
	isc_region_t r;
	dns_name_t name;

	REQUIRE(rdata->type == dns_rdatatype_mf);
	REQUIRE(target != NULL);
	REQUIRE(rdata->length != 0);

	mf->common.rdclass = rdata->rdclass;
	mf->common.rdtype = rdata->type;
	ISC_LINK_INIT(&mf->common, link);

	dns_name_init(&name, NULL);
	dns_rdata_toregion(rdata, &r);
	dns_name_fromregion(&name, &r);
	dns_name_init(&mf->mf, NULL);
	RETERR(name_duporclone(&name, &mf->mf));
	return (ISC_R_SUCCESS);
}

static inline void
freestruct_mf(ARGS_FREESTRUCT) {
	dns_rdata_mf_t *mf = source;

	REQUIRE(source != NULL);
	REQUIRE(mf->common.rdtype == dns_rdatatype_mf);

	dns_name_free(&mf->mf);
}



#endif	/* RDATA_GENERIC_MF_4_C */
