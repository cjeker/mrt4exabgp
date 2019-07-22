#	$OpenBSD: Makefile,v 1.15 2019/06/25 07:44:20 claudio Exp $

BINDIR?=	/usr/local/bin

PROG=	mrt4exabgp
SRCS=	mrt4exabgp.c mrtparser.c util.c
MAN=
CFLAGS+= -Wall
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
CFLAGS+= -I${.CURDIR}
LDADD+=	-lpthread
DPADD+=	${LIBPTHREAD}

.include <bsd.prog.mk>
