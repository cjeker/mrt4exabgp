/*	$OpenBSD: bgpd.h,v 1.388 2019/06/22 05:36:40 claudio Exp $ */

/*
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

/* Address Family Numbers as per RFC 1700 */
#define	AFI_UNSPEC	0
#define	AFI_IPv4	1
#define	AFI_IPv6	2

/* Subsequent Address Family Identifier as per RFC 4760 */
#define	SAFI_NONE	0
#define	SAFI_UNICAST	1
#define	SAFI_MULTICAST	2
#define	SAFI_MPLS	4
#define	SAFI_MPLSVPN	128

struct aid {
	u_int16_t	 afi;
	u_int8_t	 safi;
	char		*name;
};

extern const struct aid aid_vals[];

#define	AID_UNSPEC	0
#define	AID_INET	1
#define	AID_INET6	2
#define	AID_VPN_IPv4	3
#define	AID_VPN_IPv6	4
#define	AID_MAX		5
#define	AID_MIN		1	/* skip AID_UNSPEC since that is a dummy */

#define AID_VALS	{					\
	/* afi, safii, name */				\
	{ AFI_UNSPEC, SAFI_NONE, "unspec"},		\
	{ AFI_IPv4, SAFI_UNICAST, "IPv4 unicast" },	\
	{ AFI_IPv6, SAFI_UNICAST, "IPv6 unicast" },	\
	{ AFI_IPv4, SAFI_MPLSVPN, "IPv4 vpn" },	\
	{ AFI_IPv6, SAFI_MPLSVPN, "IPv6 vpn" }	\
}

struct vpn4_addr {
	u_int64_t	rd;
	struct in_addr	addr;
	u_int8_t	labelstack[21];	/* max that makes sense */
	u_int8_t	labellen;
	u_int8_t	pad1;
	u_int8_t	pad2;
};

struct vpn6_addr {
	u_int64_t	rd;
	struct in6_addr	addr;
	u_int8_t	labelstack[21];	/* max that makes sense */
	u_int8_t	labellen;
	u_int8_t	pad1;
	u_int8_t	pad2;
};

#define BGP_MPLS_BOS	0x01

struct bgpd_addr {
	union {
		struct in_addr		v4;
		struct in6_addr		v6;
		struct vpn4_addr	vpn4;
		struct vpn6_addr	vpn6;
		/* maximum size for a prefix is 256 bits */
		u_int8_t		addr8[32];
		u_int16_t		addr16[16];
		u_int32_t		addr32[8];
	} ba;		    /* 128-bit address */
	u_int32_t	scope_id;	/* iface scope id for v6 */
	u_int8_t	aid;
#define	v4	ba.v4
#define	v6	ba.v6
#define	vpn4	ba.vpn4
#define	vpn6	ba.vpn6
#define	addr8	ba.addr8
#define	addr16	ba.addr16
#define	addr32	ba.addr32
};

enum attrtypes {
	ATTR_UNDEF,
	ATTR_ORIGIN,
	ATTR_ASPATH,
	ATTR_NEXTHOP,
	ATTR_MED,
	ATTR_LOCALPREF,
	ATTR_ATOMIC_AGGREGATE,
	ATTR_AGGREGATOR,
	ATTR_COMMUNITIES,
	ATTR_ORIGINATOR_ID,
	ATTR_CLUSTER_LIST,
	ATTR_MP_REACH_NLRI=14,
	ATTR_MP_UNREACH_NLRI=15,
	ATTR_EXT_COMMUNITIES=16,
	ATTR_AS4_PATH=17,
	ATTR_AS4_AGGREGATOR=18,
	ATTR_LARGE_COMMUNITIES=32,
	ATTR_FIRST_UNKNOWN,	/* after this all attributes are unknown */
};

/* attribute flags. 4 low order bits reserved */
#define	ATTR_EXTLEN		0x10
#define ATTR_PARTIAL		0x20
#define ATTR_TRANSITIVE		0x40
#define ATTR_OPTIONAL		0x80
#define ATTR_RESERVED		0x0f
/* by default mask the reserved bits and the ext len bit */
#define ATTR_DEFMASK		(ATTR_RESERVED | ATTR_EXTLEN)

/* default attribute flags for well known attributes */
#define ATTR_WELL_KNOWN		ATTR_TRANSITIVE

#define AS_SET			1
#define AS_SEQUENCE		2
#define AS_CONFED_SEQUENCE	3
#define AS_CONFED_SET		4

/* extended community definitions */
#define EXT_COMMUNITY_IANA		0x80
#define EXT_COMMUNITY_NON_TRANSITIVE	0x40
#define EXT_COMMUNITY_VALUE		0x3f
/* extended types transitive */
#define EXT_COMMUNITY_TRANS_TWO_AS	0x00	/* 2 octet AS specific */
#define EXT_COMMUNITY_TRANS_IPV4	0x01	/* IPv4 specific */
#define EXT_COMMUNITY_TRANS_FOUR_AS	0x02	/* 4 octet AS specific */
#define EXT_COMMUNITY_TRANS_OPAQUE	0x03	/* opaque ext community */
#define EXT_COMMUNITY_TRANS_EVPN	0x06	/* EVPN RFC7432 */
/* extended types non-transitive */
#define EXT_COMMUNITY_NON_TRANS_TWO_AS	0x40	/* 2 octet AS specific */
#define EXT_COMMUNITY_NON_TRANS_IPV4	0x41	/* IPv4 specific */
#define EXT_COMMUNITY_NON_TRANS_FOUR_AS	0x42	/* 4 octet AS specific */
#define EXT_COMMUNITY_NON_TRANS_OPAQUE	0x43	/* opaque ext community */
#define EXT_COMMUNITY_UNKNOWN		-1


const char	*log_addr(const struct bgpd_addr *);
const char	*log_rd(u_int64_t);

int	aspath_asprint(char **, void *, u_int16_t);
void	sa2addr(struct sockaddr *, struct bgpd_addr *, u_int16_t *);

int	nlri_get_prefix(u_char *, u_int16_t, struct bgpd_addr *, u_int8_t *);
int	nlri_get_prefix6(u_char *, u_int16_t, struct bgpd_addr *, u_int8_t *);
int	nlri_get_vpn4(u_char *, u_int16_t, struct bgpd_addr *, u_int8_t *, int);
int	nlri_get_vpn6(u_char *, u_int16_t, struct bgpd_addr *, u_int8_t *, int);
