/*	$OpenBSD: util.c,v 1.50 2019/06/17 13:35:43 claudio Exp $ */

/*
 * Copyright (c) 2006 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bgpd.h"

const char *
log_addr(const struct bgpd_addr *addr)
{
	static char	buf[74];
	char		tbuf[40];
	int		af = AF_INET;

	switch (addr->aid) {
	case AID_INET6:
		af = AF_INET6;
		/* FALLTHROUGH */
	case AID_INET:
		if (inet_ntop(af, &addr->ba, buf, sizeof(buf)) == NULL)
			return ("?");
		return (buf);
	case AID_VPN_IPv4:
		if (inet_ntop(AF_INET, &addr->vpn4.addr, tbuf,
		    sizeof(tbuf)) == NULL)
			return ("?");
		snprintf(buf, sizeof(buf), "%s %s", log_rd(addr->vpn4.rd),
		    tbuf);
		return (buf);
	case AID_VPN_IPv6:
		if (inet_ntop(AF_INET6, &addr->vpn6.addr, tbuf,
		    sizeof(tbuf)) == NULL)
			return ("?");
		snprintf(buf, sizeof(buf), "%s %s", log_rd(addr->vpn6.rd),
		    tbuf);
		return (buf);
	}
	return ("???");
}

const char *
log_rd(u_int64_t rd)
{
	static char	buf[32];
	struct in_addr	addr;
	u_int32_t	u32;
	u_int16_t	u16;

	rd = be64toh(rd);
	switch (rd >> 48) {
	case EXT_COMMUNITY_TRANS_TWO_AS:
		u32 = rd & 0xffffffff;
		u16 = (rd >> 32) & 0xffff;
		snprintf(buf, sizeof(buf), "rd %hu:%u", u16, u32);
		break;
	case EXT_COMMUNITY_TRANS_FOUR_AS:
		u32 = (rd >> 16) & 0xffffffff;
		u16 = rd & 0xffff;
		snprintf(buf, sizeof(buf), "rd %u:%hu", u32, u16);
		break;
	case EXT_COMMUNITY_TRANS_IPV4:
		u32 = (rd >> 16) & 0xffffffff;
		u16 = rd & 0xffff;
		addr.s_addr = htonl(u32);
		snprintf(buf, sizeof(buf), "rd %s:%hu", inet_ntoa(addr), u16);
		break;
	default:
		return ("rd ?");
	}
	return (buf);
}

static const char *
aspath_delim(u_int8_t seg_type, int closing)
{
	static char db[8];

	switch (seg_type) {
	case AS_SET:
		if (!closing)
			return ("( ");
		else
			return (" )");
	case AS_SEQUENCE:
		return ("");
	case AS_CONFED_SEQUENCE:
		if (!closing)
			return ("[ ");
		else
			return (" ]");
	case AS_CONFED_SET:
		if (!closing)
			return ("{ ");
		else
			return (" }");
	default:
		if (!closing)
			snprintf(db, sizeof(db), "!%u ", seg_type);
		else
			snprintf(db, sizeof(db), " !%u", seg_type);
		return (db);
	}
}

/*
 * Extract the asnum out of the as segment at the specified position.
 * Direct access is not possible because of non-aligned reads.
 * ATTENTION: no bounds checks are done.
 */
static u_int32_t
aspath_extract(const void *seg, int pos)
{
	const u_char	*ptr = seg;
	u_int32_t	 as;

	ptr += 2 + sizeof(u_int32_t) * pos;
	memcpy(&as, ptr, sizeof(u_int32_t));
	return (ntohl(as));
}

static int
aspath_snprint(char *buf, size_t size, void *data, u_int16_t len)
{
#define UPDATE()				\
	do {					\
		if (r == -1)			\
			return (-1);		\
		total_size += r;		\
		if ((unsigned int)r < size) {	\
			size -= r;		\
			buf += r;		\
		} else {			\
			buf += size;		\
			size = 0;		\
		}				\
	} while (0)
	u_int8_t	*seg;
	int		 r, total_size;
	u_int16_t	 seg_size;
	u_int8_t	 i, seg_type, seg_len;

	total_size = 0;
	seg = data;
	for (; len > 0; len -= seg_size, seg += seg_size) {
		seg_type = seg[0];
		seg_len = seg[1];
		seg_size = 2 + sizeof(u_int32_t) * seg_len;

		r = snprintf(buf, size, "%s%s",
		    total_size != 0 ? " " : "",
		    aspath_delim(seg_type, 0));
		UPDATE();

		for (i = 0; i < seg_len; i++) {
			r = snprintf(buf, size, "%u", aspath_extract(seg, i));
			UPDATE();
			if (i + 1 < seg_len) {
				r = snprintf(buf, size, " ");
				UPDATE();
			}
		}
		r = snprintf(buf, size, "%s", aspath_delim(seg_type, 1));
		UPDATE();
	}
	/* ensure that we have a valid C-string especially for empty as path */
	if (size > 0)
		*buf = '\0';

	return (total_size);
#undef UPDATE
}

static size_t
aspath_strlen(void *data, u_int16_t len)
{
	u_int8_t	*seg;
	int		 total_size;
	u_int32_t	 as;
	u_int16_t	 seg_size;
	u_int8_t	 i, seg_type, seg_len;

	total_size = 0;
	seg = data;
	for (; len > 0; len -= seg_size, seg += seg_size) {
		seg_type = seg[0];
		seg_len = seg[1];
		seg_size = 2 + sizeof(u_int32_t) * seg_len;

		if (seg_type == AS_SET)
			if (total_size != 0)
				total_size += 3;
			else
				total_size += 2;
		else if (total_size != 0)
			total_size += 1;

		for (i = 0; i < seg_len; i++) {
			as = aspath_extract(seg, i);

			do {
				total_size++;
			} while ((as = as / 10) != 0);

			if (i + 1 < seg_len)
				total_size += 1;
		}

		if (seg_type == AS_SET)
			total_size += 2;
	}
	return (total_size);
}
int
aspath_asprint(char **ret, void *data, u_int16_t len)
{
	size_t	slen;
	int	plen;

	slen = aspath_strlen(data, len) + 1;
	*ret = malloc(slen);
	if (*ret == NULL)
		return (-1);

	plen = aspath_snprint(*ret, slen, data, len);
	if (plen == -1) {
		free(*ret);
		*ret = NULL;
		return (-1);
	}

	return (0);
}

/* NLRI functions to extract prefixes from the NLRI blobs */
static int
extract_prefix(u_char *p, u_int16_t len, void *va,
    u_int8_t pfxlen, u_int8_t max)
{
	static u_char addrmask[] = {
	    0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff };
	u_char		*a = va;
	int		 i;
	u_int16_t	 plen = 0;

	for (i = 0; pfxlen && i < max; i++) {
		if (len <= plen)
			return (-1);
		if (pfxlen < 8) {
			a[i] = *p++ & addrmask[pfxlen];
			plen++;
			break;
		} else {
			a[i] = *p++;
			plen++;
			pfxlen -= 8;
		}
	}
	return (plen);
}

int
nlri_get_prefix(u_char *p, u_int16_t len, struct bgpd_addr *prefix,
    u_int8_t *prefixlen)
{
	u_int8_t	 pfxlen;
	int		 plen;

	if (len < 1)
		return (-1);

	pfxlen = *p++;
	len--;

	memset(prefix, 0, sizeof(struct bgpd_addr));
	prefix->aid = AID_INET;
	*prefixlen = pfxlen;

	if (pfxlen > 32)
		return (-1);
	if ((plen = extract_prefix(p, len, &prefix->v4, pfxlen,
	    sizeof(prefix->v4))) == -1)
		return (-1);

	return (plen + 1);	/* pfxlen needs to be added */
}

int
nlri_get_prefix6(u_char *p, u_int16_t len, struct bgpd_addr *prefix,
    u_int8_t *prefixlen)
{
	int		plen;
	u_int8_t	pfxlen;

	if (len < 1)
		return (-1);

	pfxlen = *p++;
	len--;

	memset(prefix, 0, sizeof(struct bgpd_addr));
	prefix->aid = AID_INET6;
	*prefixlen = pfxlen;

	if (pfxlen > 128)
		return (-1);
	if ((plen = extract_prefix(p, len, &prefix->v6, pfxlen,
	    sizeof(prefix->v6))) == -1)
		return (-1);

	return (plen + 1);	/* pfxlen needs to be added */
}

int
nlri_get_vpn4(u_char *p, u_int16_t len, struct bgpd_addr *prefix,
    u_int8_t *prefixlen, int withdraw)
{
	int		 rv, done = 0;
	u_int8_t	 pfxlen;
	u_int16_t	 plen;

	if (len < 1)
		return (-1);

	memcpy(&pfxlen, p, 1);
	p += 1;
	plen = 1;

	memset(prefix, 0, sizeof(struct bgpd_addr));

	/* label stack */
	do {
		if (len - plen < 3 || pfxlen < 3 * 8)
			return (-1);
		if (prefix->vpn4.labellen + 3U >
		    sizeof(prefix->vpn4.labelstack))
			return (-1);
		if (withdraw) {
			/* on withdraw ignore the labelstack all together */
			plen += 3;
			pfxlen -= 3 * 8;
			break;
		}
		prefix->vpn4.labelstack[prefix->vpn4.labellen++] = *p++;
		prefix->vpn4.labelstack[prefix->vpn4.labellen++] = *p++;
		prefix->vpn4.labelstack[prefix->vpn4.labellen] = *p++;
		if (prefix->vpn4.labelstack[prefix->vpn4.labellen] &
		    BGP_MPLS_BOS)
			done = 1;
		prefix->vpn4.labellen++;
		plen += 3;
		pfxlen -= 3 * 8;
	} while (!done);

	/* RD */
	if (len - plen < (int)sizeof(u_int64_t) ||
	    pfxlen < sizeof(u_int64_t) * 8)
		return (-1);
	memcpy(&prefix->vpn4.rd, p, sizeof(u_int64_t));
	pfxlen -= sizeof(u_int64_t) * 8;
	p += sizeof(u_int64_t);
	plen += sizeof(u_int64_t);

	/* prefix */
	prefix->aid = AID_VPN_IPv4;
	*prefixlen = pfxlen;

	if (pfxlen > 32)
		return (-1);
	if ((rv = extract_prefix(p, len, &prefix->vpn4.addr,
	    pfxlen, sizeof(prefix->vpn4.addr))) == -1)
		return (-1);

	return (plen + rv);
}

int
nlri_get_vpn6(u_char *p, u_int16_t len, struct bgpd_addr *prefix,
    u_int8_t *prefixlen, int withdraw)
{
	int		rv, done = 0;
	u_int8_t	pfxlen;
	u_int16_t	plen;

	if (len < 1)
		return (-1);

	memcpy(&pfxlen, p, 1);
	p += 1;
	plen = 1;

	memset(prefix, 0, sizeof(struct bgpd_addr));

	/* label stack */
	do {
		if (len - plen < 3 || pfxlen < 3 * 8)
			return (-1);
		if (prefix->vpn6.labellen + 3U >
		    sizeof(prefix->vpn6.labelstack))
			return (-1);
		if (withdraw) {
			/* on withdraw ignore the labelstack all together */
			plen += 3;
			pfxlen -= 3 * 8;
			break;
		}

		prefix->vpn6.labelstack[prefix->vpn6.labellen++] = *p++;
		prefix->vpn6.labelstack[prefix->vpn6.labellen++] = *p++;
		prefix->vpn6.labelstack[prefix->vpn6.labellen] = *p++;
		if (prefix->vpn6.labelstack[prefix->vpn6.labellen] &
		    BGP_MPLS_BOS)
			done = 1;
		prefix->vpn6.labellen++;
		plen += 3;
		pfxlen -= 3 * 8;
	} while (!done);

	/* RD */
	if (len - plen < (int)sizeof(u_int64_t) ||
	    pfxlen < sizeof(u_int64_t) * 8)
		return (-1);

	memcpy(&prefix->vpn6.rd, p, sizeof(u_int64_t));
	pfxlen -= sizeof(u_int64_t) * 8;
	p += sizeof(u_int64_t);
	plen += sizeof(u_int64_t);

	/* prefix */
	prefix->aid = AID_VPN_IPv6;
	*prefixlen = pfxlen;

	if (pfxlen > 128)
		return (-1);

	if ((rv = extract_prefix(p, len, &prefix->vpn6.addr,
	    pfxlen, sizeof(prefix->vpn6.addr))) == -1)
		return (-1);

	return (plen + rv);
}

#if 0
/* address family translation functions */
const struct aid aid_vals[AID_MAX] = AID_VALS;

const char *
aid2str(u_int8_t aid)
{
	if (aid < AID_MAX)
		return (aid_vals[aid].name);
	return ("unknown AID");
}

int
aid2afi(u_int8_t aid, u_int16_t *afi, u_int8_t *safi)
{
	if (aid < AID_MAX) {
		*afi = aid_vals[aid].afi;
		*safi = aid_vals[aid].safi;
		return (0);
	}
	return (-1);
}

int
afi2aid(u_int16_t afi, u_int8_t safi, u_int8_t *aid)
{
	u_int8_t i;

	for (i = 0; i < AID_MAX; i++)
		if (aid_vals[i].afi == afi && aid_vals[i].safi == safi) {
			*aid = i;
			return (0);
		}

	return (-1);
}
#endif

void
sa2addr(struct sockaddr *sa, struct bgpd_addr *addr, u_int16_t *port)
{
	struct sockaddr_in		*sa_in = (struct sockaddr_in *)sa;
	struct sockaddr_in6		*sa_in6 = (struct sockaddr_in6 *)sa;

	memset(addr, 0, sizeof(*addr));
	switch (sa->sa_family) {
	case AF_INET:
		addr->aid = AID_INET;
		memcpy(&addr->v4, &sa_in->sin_addr, sizeof(addr->v4));
		if (port)
			*port = ntohs(sa_in->sin_port);
		break;
	case AF_INET6:
		addr->aid = AID_INET6;
		memcpy(&addr->v6, &sa_in6->sin6_addr, sizeof(addr->v6));
		addr->scope_id = sa_in6->sin6_scope_id; /* I hate v6 */
		if (port)
			*port = ntohs(sa_in6->sin6_port);
		break;
	}
}
