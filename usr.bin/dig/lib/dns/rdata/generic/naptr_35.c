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

/* $Id: naptr_35.c,v 1.5 2020/02/24 12:06:51 florian Exp $ */

/* Reviewed: Thu Mar 16 16:52:50 PST 2000 by bwelling */

/* RFC2915 */

#ifndef RDATA_GENERIC_NAPTR_35_C
#define RDATA_GENERIC_NAPTR_35_C

#define RRTYPE_NAPTR_ATTRIBUTES (0)

#include <isc/regex.h>

/*
 * Check the wire format of the Regexp field.
 * Don't allow embeded NUL's.
 */
static inline isc_result_t
txt_valid_regex(const unsigned char *txt) {
	unsigned int nsub = 0;
	char regex[256];
	char *cp;
	isc_boolean_t flags = ISC_FALSE;
	isc_boolean_t replace = ISC_FALSE;
	unsigned char c;
	unsigned char delim;
	unsigned int len;
	int n;

	len = *txt++;
	if (len == 0U)
		return (ISC_R_SUCCESS);

	delim = *txt++;
	len--;

	/*
	 * Digits, backslash and flags can't be delimiters.
	 */
	switch (delim) {
	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
	case '\\': case 'i': case 0:
		return (DNS_R_SYNTAX);
	}

	cp = regex;
	while (len-- > 0) {
		c = *txt++;
		if (c == 0)
			return (DNS_R_SYNTAX);
		if (c == delim && !replace) {
			replace = ISC_TRUE;
			continue;
		} else if (c == delim && !flags) {
			flags = ISC_TRUE;
			continue;
		} else if (c == delim)
			return (DNS_R_SYNTAX);
		/*
		 * Flags are not escaped.
		 */
		if (flags) {
			switch (c) {
			case 'i':
				continue;
			default:
				return (DNS_R_SYNTAX);
			}
		}
		if (!replace)
			*cp++ = c;
		if (c == '\\') {
			if (len == 0)
				return (DNS_R_SYNTAX);
			c = *txt++;
			if (c == 0)
				return (DNS_R_SYNTAX);
			len--;
			if (replace)
				switch (c) {
				case '0': return (DNS_R_SYNTAX);
				case '1': if (nsub < 1) nsub = 1; break;
				case '2': if (nsub < 2) nsub = 2; break;
				case '3': if (nsub < 3) nsub = 3; break;
				case '4': if (nsub < 4) nsub = 4; break;
				case '5': if (nsub < 5) nsub = 5; break;
				case '6': if (nsub < 6) nsub = 6; break;
				case '7': if (nsub < 7) nsub = 7; break;
				case '8': if (nsub < 8) nsub = 8; break;
				case '9': if (nsub < 9) nsub = 9; break;
				}
			if (!replace)
				*cp++ = c;
		}
	}
	if (!flags)
		return (DNS_R_SYNTAX);
	*cp = '\0';
	n = isc_regex_validate(regex);
	if (n < 0 || nsub > (unsigned int)n)
		return (DNS_R_SYNTAX);
	return (ISC_R_SUCCESS);
}

static inline isc_result_t
totext_naptr(ARGS_TOTEXT) {
	isc_region_t region;
	dns_name_t name;
	dns_name_t prefix;
	isc_boolean_t sub;
	char buf[sizeof("64000")];
	unsigned short num;

	REQUIRE(rdata->type == dns_rdatatype_naptr);
	REQUIRE(rdata->length != 0);

	dns_name_init(&name, NULL);
	dns_name_init(&prefix, NULL);

	dns_rdata_toregion(rdata, &region);

	/*
	 * Order.
	 */
	num = uint16_fromregion(&region);
	isc_region_consume(&region, 2);
	snprintf(buf, sizeof(buf), "%u", num);
	RETERR(str_totext(buf, target));
	RETERR(str_totext(" ", target));

	/*
	 * Preference.
	 */
	num = uint16_fromregion(&region);
	isc_region_consume(&region, 2);
	snprintf(buf, sizeof(buf), "%u", num);
	RETERR(str_totext(buf, target));
	RETERR(str_totext(" ", target));

	/*
	 * Flags.
	 */
	RETERR(txt_totext(&region, ISC_TRUE, target));
	RETERR(str_totext(" ", target));

	/*
	 * Service.
	 */
	RETERR(txt_totext(&region, ISC_TRUE, target));
	RETERR(str_totext(" ", target));

	/*
	 * Regexp.
	 */
	RETERR(txt_totext(&region, ISC_TRUE, target));
	RETERR(str_totext(" ", target));

	/*
	 * Replacement.
	 */
	dns_name_fromregion(&name, &region);
	sub = name_prefix(&name, tctx->origin, &prefix);
	return (dns_name_totext(&prefix, sub, target));
}

static inline isc_result_t
fromwire_naptr(ARGS_FROMWIRE) {
	dns_name_t name;
	isc_region_t sr;
	unsigned char *regex;

	REQUIRE(type == dns_rdatatype_naptr);

	UNUSED(type);
	UNUSED(rdclass);

	dns_decompress_setmethods(dctx, DNS_COMPRESS_NONE);

	dns_name_init(&name, NULL);

	/*
	 * Order, preference.
	 */
	isc_buffer_activeregion(source, &sr);
	if (sr.length < 4)
		return (ISC_R_UNEXPECTEDEND);
	RETERR(mem_tobuffer(target, sr.base, 4));
	isc_buffer_forward(source, 4);

	/*
	 * Flags.
	 */
	RETERR(txt_fromwire(source, target));

	/*
	 * Service.
	 */
	RETERR(txt_fromwire(source, target));

	/*
	 * Regexp.
	 */
	regex = isc_buffer_used(target);
	RETERR(txt_fromwire(source, target));
	RETERR(txt_valid_regex(regex));

	/*
	 * Replacement.
	 */
	return (dns_name_fromwire(&name, source, dctx, options, target));
}

static inline isc_result_t
towire_naptr(ARGS_TOWIRE) {
	dns_name_t name;
	dns_offsets_t offsets;
	isc_region_t sr;

	REQUIRE(rdata->type == dns_rdatatype_naptr);
	REQUIRE(rdata->length != 0);

	dns_compress_setmethods(cctx, DNS_COMPRESS_NONE);
	/*
	 * Order, preference.
	 */
	dns_rdata_toregion(rdata, &sr);
	RETERR(mem_tobuffer(target, sr.base, 4));
	isc_region_consume(&sr, 4);

	/*
	 * Flags.
	 */
	RETERR(mem_tobuffer(target, sr.base, sr.base[0] + 1));
	isc_region_consume(&sr, sr.base[0] + 1);

	/*
	 * Service.
	 */
	RETERR(mem_tobuffer(target, sr.base, sr.base[0] + 1));
	isc_region_consume(&sr, sr.base[0] + 1);

	/*
	 * Regexp.
	 */
	RETERR(mem_tobuffer(target, sr.base, sr.base[0] + 1));
	isc_region_consume(&sr, sr.base[0] + 1);

	/*
	 * Replacement.
	 */
	dns_name_init(&name, offsets);
	dns_name_fromregion(&name, &sr);
	return (dns_name_towire(&name, cctx, target));
}


static inline isc_result_t
fromstruct_naptr(ARGS_FROMSTRUCT) {
	dns_rdata_naptr_t *naptr = source;
	isc_region_t region;

	REQUIRE(type == dns_rdatatype_naptr);
	REQUIRE(source != NULL);
	REQUIRE(naptr->common.rdtype == type);
	REQUIRE(naptr->common.rdclass == rdclass);
	REQUIRE(naptr->flags != NULL || naptr->flags_len == 0);
	REQUIRE(naptr->service != NULL || naptr->service_len == 0);
	REQUIRE(naptr->regexp != NULL || naptr->regexp_len == 0);

	UNUSED(type);
	UNUSED(rdclass);

	RETERR(uint16_tobuffer(naptr->order, target));
	RETERR(uint16_tobuffer(naptr->preference, target));
	RETERR(uint8_tobuffer(naptr->flags_len, target));
	RETERR(mem_tobuffer(target, naptr->flags, naptr->flags_len));
	RETERR(uint8_tobuffer(naptr->service_len, target));
	RETERR(mem_tobuffer(target, naptr->service, naptr->service_len));
	RETERR(uint8_tobuffer(naptr->regexp_len, target));
	RETERR(mem_tobuffer(target, naptr->regexp, naptr->regexp_len));
	dns_name_toregion(&naptr->replacement, &region);
	return (isc_buffer_copyregion(target, &region));
}

static inline isc_result_t
tostruct_naptr(ARGS_TOSTRUCT) {
	dns_rdata_naptr_t *naptr = target;
	isc_region_t r;
	isc_result_t result;
	dns_name_t name;

	REQUIRE(rdata->type == dns_rdatatype_naptr);
	REQUIRE(target != NULL);
	REQUIRE(rdata->length != 0);

	naptr->common.rdclass = rdata->rdclass;
	naptr->common.rdtype = rdata->type;
	ISC_LINK_INIT(&naptr->common, link);

	naptr->flags = NULL;
	naptr->service = NULL;
	naptr->regexp = NULL;

	dns_rdata_toregion(rdata, &r);

	naptr->order = uint16_fromregion(&r);
	isc_region_consume(&r, 2);

	naptr->preference = uint16_fromregion(&r);
	isc_region_consume(&r, 2);

	naptr->flags_len = uint8_fromregion(&r);
	isc_region_consume(&r, 1);
	INSIST(naptr->flags_len <= r.length);
	naptr->flags = mem_maybedup(r.base, naptr->flags_len);
	if (naptr->flags == NULL)
		goto cleanup;
	isc_region_consume(&r, naptr->flags_len);

	naptr->service_len = uint8_fromregion(&r);
	isc_region_consume(&r, 1);
	INSIST(naptr->service_len <= r.length);
	naptr->service = mem_maybedup(r.base, naptr->service_len);
	if (naptr->service == NULL)
		goto cleanup;
	isc_region_consume(&r, naptr->service_len);

	naptr->regexp_len = uint8_fromregion(&r);
	isc_region_consume(&r, 1);
	INSIST(naptr->regexp_len <= r.length);
	naptr->regexp = mem_maybedup(r.base, naptr->regexp_len);
	if (naptr->regexp == NULL)
		goto cleanup;
	isc_region_consume(&r, naptr->regexp_len);

	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &r);
	dns_name_init(&naptr->replacement, NULL);
	result = name_duporclone(&name, &naptr->replacement);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	return (ISC_R_SUCCESS);

 cleanup:
	free(naptr->flags);
	free(naptr->service);
	free(naptr->regexp);
	return (ISC_R_NOMEMORY);
}

static inline void
freestruct_naptr(ARGS_FREESTRUCT) {
	dns_rdata_naptr_t *naptr = source;

	REQUIRE(source != NULL);
	REQUIRE(naptr->common.rdtype == dns_rdatatype_naptr);

	free(naptr->flags);
	free(naptr->service);
	free(naptr->regexp);
	dns_name_free(&naptr->replacement);
}



#endif	/* RDATA_GENERIC_NAPTR_35_C */
