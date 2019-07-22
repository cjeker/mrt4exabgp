/*
 * Copyright (c) 2019 Claudio Jeker <claudio@openbsd.org>
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
#include <endian.h>
#include <err.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "mrtparser.h"

struct bgpd_addr neighbor;
u_int8_t aid;

static void
show_community(u_char *data, size_t len)
{
	size_t i;
	u_int16_t a, v;

	printf(" community [ ");
	for (i = 0; i < len; i += 4) {
		memcpy(&a, data + i, sizeof(a));
		memcpy(&v, data + i + 2, sizeof(v));
		printf("%hu:%hu ", ntohs(a), ntohs(v));
	}
	printf("]");
}

static void
show_ext_community(u_char *data, size_t len)
{
	size_t i;
	u_int64_t v;

	printf(" extended-community [ ");
	for (i = 0; i < len; i += 4) {
		memcpy(&v, data + i, sizeof(v));
		printf("0x%016llx ", be64toh(v));
	}
	printf("]");
}

static void
show_large_community(u_char *data, size_t len)
{
	size_t i;
	u_int32_t a, v1, v2;

#if 0
	printf(" large-community [ ");
	for (i = 0; i < len; i += 12) {
		memcpy(&a, data + i, sizeof(a));
		memcpy(&v1, data + i + 4, sizeof(v1));
		memcpy(&v2, data + i + 8, sizeof(v2));
		printf("%u:%u:%u ", ntohl(a), ntohl(v1), ntohl(v2));
	}
	printf("]");
#else
	/* exabgp in ports does not support large-community */

	printf(" attribute [ 0x%02x 0x%02x 0x", ATTR_LARGE_COMMUNITIES,
	     ATTR_OPTIONAL | ATTR_TRANSITIVE);
	for (i = 0; i < len; i += 12) {
		memcpy(&a, data + i, sizeof(a));
		memcpy(&v1, data + i + 4, sizeof(v1));
		memcpy(&v2, data + i + 8, sizeof(v2));
		printf("%08x%08x%08x", ntohl(a), ntohl(v1), ntohl(v2));
	}
	printf(" ]");
#endif
}

static void
show_attr(void *b, size_t len)
{
	u_char	*data = b;
	u_int16_t tmp;
	u_int8_t flags, type;
	size_t alen;


	if (len < 3)
		errx(1, "%s: too short bgp attr", __func__);
	flags = data[0];
	type = data[1];
	/* get the attribute length */
	if (flags & ATTR_EXTLEN) {
		if (len < 4)
			errx(1, "%s: too short bgp attr", __func__);
		memcpy(&tmp, data+2, sizeof(tmp));
		alen = ntohs(tmp);
		data += 4;
		len -= 4;
	} else {
		alen = data[2];
		data += 3;
		len -= 3;
	}
	if (alen != len)
		errx(1, "%s: bad length", __func__);

	switch (type) {
	case ATTR_COMMUNITIES:
		if (len % 4)
			errx(1, "%s: bad length", __func__);
		show_community(data, len);
		break;
	case ATTR_EXT_COMMUNITIES:
		if (len % 8)
			errx(1, "%s: bad length", __func__);
		show_ext_community(data, len);
		break;
	case ATTR_LARGE_COMMUNITIES:
		if (len % 12)
			errx(1, "%s: bad length", __func__);
		show_large_community(data, len);
		break;
	}
}

static void
mrt_exa_dump(struct mrt_rib *mr, struct mrt_peer *mp, void *arg)
{
	struct mrt_rib_entry *mre;
	int i, j;
	char *asstr;

	for (i = 0; i < mr->nentries; i++) {
		/* filter by AF */
		if (aid && aid != mr->prefix.aid)
			return;

		mre = &mr->entries[i];
		if (mre->peer_idx >= mp->npeers)
			errx(1, "bad peer index");
		/* filter by neighbor */
		if (memcmp(&mp->peers[mre->peer_idx].addr, &neighbor,
		    sizeof(neighbor)) != 0)
			continue;

		printf("announce route %s/%d", log_addr(&mr->prefix),
		    mr->prefixlen);
		printf(" next-hop %s", log_addr(&mre->nexthop));

		/* aspath */
		if (aspath_asprint(&asstr, mre->aspath, mre->aspath_len) == -1)
			err(1, "aspath_asprint");
		printf(" as-path [ %s ]", asstr); 
		free(asstr);

		/* basic attrs */
		printf(" origin %s", mre->origin == 0 ? "igp" :
		    mre->origin == 1 ? "egp" : "incomplete");
		if (mre->med)
			printf(" med %u", mre->med);
		if (mre->local_pref)
			printf(" local-preference %u", mre->local_pref);

		/* all other atributes */
		for (j = 0; j < mre->nattrs; j++)
			show_attr(mre->attrs[j].attr, mre->attrs[j].attr_len);

		printf("\n");
		fflush(stdout);	/* force the command out */
	}
}

struct mrt_parser exadump = { mrt_exa_dump, NULL, NULL };

static __dead void
usage(void)
{
	extern char     *__progname;

	fprintf(stderr, "usage: %s [-46] -n addr mrtdump\n",
	    __progname);
	exit(1);
}

static int
parse_addr(const char *word, struct bgpd_addr *addr)
{
	struct addrinfo	hints, *r;

	memset(addr, 0, sizeof(*addr));
	if (word == NULL)
		return (0);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM; /*dummy*/
	hints.ai_flags = AI_NUMERICHOST;
	if (getaddrinfo(word, "0", &hints, &r) == 0) {
		sa2addr(r->ai_addr, addr, NULL);
		freeaddrinfo(r);
		return (1);
	}

	return (0);
}

static void *
reader(void *arg)
{
	char *line = NULL;
	size_t len = 0;
	ssize_t n;

	while ((n = getline(&line, &len, stdin)) != -1) {
		if (n <= 1)
			continue;
		fprintf(stderr, "mrt4exabgp got: %.*s", (int)n, line);
	}

	free(line);
	if (ferror(stdin))
		err(1, "getline");

	return NULL;
}

int
main(int argc, char **argv)
{
	pthread_t rid;
	int ch, r, fd;

	while ((ch = getopt(argc, argv, "46n:")) != -1) {
		switch (ch) {
			case '4':
				aid = AID_INET;
				break;
			case '6':
				aid = AID_INET6;
				break;
			case 'n':
				if (!parse_addr(optarg, &neighbor))
					errx(1, "bad neighbor address %s",
					    optarg);
				break;
			default:
				usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (neighbor.aid == AID_UNSPEC)
		errx(1, "no neighbor specified");
	if (argc != 1) {
		printf("argc %d\n", argc);
		usage();
	}

	fd = open(argv[0], O_RDONLY);
	if (fd == -1)
		err(1, "open(%s)", argv[0]);

	r = pthread_create(&rid, NULL, reader, NULL);
	if (r != 0)
		errc(1, r, "pthread_create");

	mrt_parse(fd, &exadump, 1);

	r = pthread_join(rid, NULL);	
	if (r != 0)
		errc(1, r, "pthread_join");
	return 0;
}
