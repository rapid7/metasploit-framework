/*	$NetBSD: getaddrinfo.c,v 1.82 2006/03/25 12:09:40 rpaulo Exp $	*/
/*	$KAME: getaddrinfo.c,v 1.29 2000/08/31 17:26:57 itojun Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Issues to be discussed:
 * - Thread safe-ness must be checked.
 * - Return values.  There are nonstandard return values defined and used
 *   in the source code.  This is because RFC2553 is silent about which error
 *   code must be returned for which situation.
 * - IPv4 classful (shortened) form.  RFC2553 is silent about it.  XNET 5.2
 *   says to use inet_aton() to convert IPv4 numeric to binary (alows
 *   classful form as a result).
 *   current code - disallow classful form for IPv4 (due to use of inet_pton).
 * - freeaddrinfo(NULL).  RFC2553 is silent about it.  XNET 5.2 says it is
 *   invalid.
 *   current code - SEGV on freeaddrinfo(NULL)
 * Note:
 * - We use getipnodebyname() just for thread-safeness.  There's no intent
 *   to let it do PF_UNSPEC (actually we never pass PF_UNSPEC to
 *   getipnodebyname().
 * - The code filters out AFs that are not supported by the kernel,
 *   when globbing NULL hostname (to loopback, or wildcard).  Is it the right
 *   thing to do?  What is the relationship with post-RFC2553 AI_ADDRCONFIG
 *   in ai_flags?
 * - (post-2553) semantics of AI_ADDRCONFIG itself is too vague.
 *   (1) what should we do against numeric hostname (2) what should we do
 *   against NULL hostname (3) what is AI_ADDRCONFIG itself.  AF not ready?
 *   non-loopback address configured?  global address configured?
 * - To avoid search order issue, we have a big amount of code duplicate
 *   from gethnamaddr.c and some other places.  The issues that there's no
 *   lower layer function to lookup "IPv4 or IPv6" record.  Calling
 *   gethostbyname2 from getaddrinfo will end up in wrong search order, as
 *   follows:
 *	- The code makes use of following calls when asked to resolver with
 *	  ai_family  = PF_UNSPEC:
 *		getipnodebyname(host, AF_INET6);
 *		getipnodebyname(host, AF_INET);
 *	  This will result in the following queries if the node is configure to
 *	  prefer /etc/hosts than DNS:
 *		lookup /etc/hosts for IPv6 address
 *		lookup DNS for IPv6 address
 *		lookup /etc/hosts for IPv4 address
 *		lookup DNS for IPv4 address
 *	  which may not meet people's requirement.
 *	  The right thing to happen is to have underlying layer which does
 *	  PF_UNSPEC lookup (lookup both) and return chain of addrinfos.
 *	  This would result in a bit of code duplicate with _dns_ghbyname() and
 *	  friends.
 */

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "arpa_nameser.h"
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include "resolv_private.h"
#include "private/resolv_private.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <syslog.h>
#include <stdarg.h>
#include "nsswitch.h"

#define SUCCESS 0
#define ANY 0
#define YES 1
#define NO  0

static const char in_addrany[] = { 0, 0, 0, 0 };
static const char in_loopback[] = { 127, 0, 0, 1 };
#ifdef INET6
static const char in6_addrany[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
static const char in6_loopback[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
};
#endif

static const struct afd {
	int a_af;
	int a_addrlen;
	int a_socklen;
	int a_off;
	const char *a_addrany;
	const char *a_loopback;
	int a_scoped;
} afdl [] = {
#ifdef INET6
	{PF_INET6, sizeof(struct in6_addr),
	 sizeof(struct sockaddr_in6),
	 offsetof(struct sockaddr_in6, sin6_addr),
	 in6_addrany, in6_loopback, 1},
#endif
	{PF_INET, sizeof(struct in_addr),
	 sizeof(struct sockaddr_in),
	 offsetof(struct sockaddr_in, sin_addr),
	 in_addrany, in_loopback, 0},
	{0, 0, 0, 0, NULL, NULL, 0},
};

struct explore {
	int e_af;
	int e_socktype;
	int e_protocol;
	const char *e_protostr;
	int e_wild;
#define WILD_AF(ex)		((ex)->e_wild & 0x01)
#define WILD_SOCKTYPE(ex)	((ex)->e_wild & 0x02)
#define WILD_PROTOCOL(ex)	((ex)->e_wild & 0x04)
};

static const struct explore explore[] = {
#if 0
	{ PF_LOCAL, 0, ANY, ANY, NULL, 0x01 },
#endif
#ifdef INET6
	{ PF_INET6, SOCK_DGRAM, IPPROTO_UDP, "udp", 0x07 },
	{ PF_INET6, SOCK_STREAM, IPPROTO_TCP, "tcp", 0x07 },
	{ PF_INET6, SOCK_RAW, ANY, NULL, 0x05 },
#endif
	{ PF_INET, SOCK_DGRAM, IPPROTO_UDP, "udp", 0x07 },
	{ PF_INET, SOCK_STREAM, IPPROTO_TCP, "tcp", 0x07 },
	{ PF_INET, SOCK_RAW, ANY, NULL, 0x05 },
	{ PF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, "udp", 0x07 },
	{ PF_UNSPEC, SOCK_STREAM, IPPROTO_TCP, "tcp", 0x07 },
	{ PF_UNSPEC, SOCK_RAW, ANY, NULL, 0x05 },
	{ -1, 0, 0, NULL, 0 },
};

#ifdef INET6
#define PTON_MAX	16
#else
#define PTON_MAX	4
#endif

static const ns_src default_dns_files[] = {
	{ NSSRC_FILES, 	NS_SUCCESS },
	{ NSSRC_DNS, 	NS_SUCCESS },
	{ 0, 0 }
};

#define MAXPACKET	(64*1024)

typedef union {
	HEADER hdr;
	u_char buf[MAXPACKET];
} querybuf;

struct res_target {
	struct res_target *next;
	const char *name;	/* domain name */
	int qclass, qtype;	/* class and type of query */
	u_char *answer;		/* buffer to put answer */
	int anslen;		/* size of answer buffer */
	int n;			/* result length */
};

static int str2number(const char *);
static int explore_fqdn(const struct addrinfo *, const char *,
	const char *, struct addrinfo **);
static int explore_null(const struct addrinfo *,
	const char *, struct addrinfo **);
static int explore_numeric(const struct addrinfo *, const char *,
	const char *, struct addrinfo **, const char *);
static int explore_numeric_scope(const struct addrinfo *, const char *,
	const char *, struct addrinfo **);
static int get_canonname(const struct addrinfo *,
	struct addrinfo *, const char *);
static struct addrinfo *get_ai(const struct addrinfo *,
	const struct afd *, const char *);
static int get_portmatch(const struct addrinfo *, const char *);
static int get_port(const struct addrinfo *, const char *, int);
static const struct afd *find_afd(int);
#ifdef INET6
static int ip6_str2scopeid(char *, struct sockaddr_in6 *, u_int32_t *);
#endif

static struct addrinfo *getanswer(const querybuf *, int, const char *, int,
	const struct addrinfo *);
static int _dns_getaddrinfo(void *, void *, va_list);
static void _sethtent(FILE **);
static void _endhtent(FILE **);
static struct addrinfo *_gethtent(FILE **, const char *,
    const struct addrinfo *);
static int _files_getaddrinfo(void *, void *, va_list);

static int res_queryN(const char *, struct res_target *, res_state);
static int res_searchN(const char *, struct res_target *, res_state);
static int res_querydomainN(const char *, const char *,
	struct res_target *, res_state);

static const char * const ai_errlist[] = {
	"Success",
	"Address family for hostname not supported",	/* EAI_ADDRFAMILY */
	"Temporary failure in name resolution",		/* EAI_AGAIN      */
	"Invalid value for ai_flags",		       	/* EAI_BADFLAGS   */
	"Non-recoverable failure in name resolution", 	/* EAI_FAIL       */
	"ai_family not supported",			/* EAI_FAMILY     */
	"Memory allocation failure", 			/* EAI_MEMORY     */
	"No address associated with hostname", 		/* EAI_NODATA     */
	"hostname nor servname provided, or not known",	/* EAI_NONAME     */
	"servname not supported for ai_socktype",	/* EAI_SERVICE    */
	"ai_socktype not supported", 			/* EAI_SOCKTYPE   */
	"System error returned in errno", 		/* EAI_SYSTEM     */
	"Invalid value for hints",			/* EAI_BADHINTS	  */
	"Resolved protocol is unknown",			/* EAI_PROTOCOL   */
	"Argument buffer overflow",			/* EAI_OVERFLOW   */
	"Unknown error", 				/* EAI_MAX        */
};

/* XXX macros that make external reference is BAD. */

#define GET_AI(ai, afd, addr) 					\
do { 								\
	/* external reference: pai, error, and label free */ 	\
	(ai) = get_ai(pai, (afd), (addr)); 			\
	if ((ai) == NULL) { 					\
		error = EAI_MEMORY; 				\
		goto free; 					\
	} 							\
} while (/*CONSTCOND*/0)

#define GET_PORT(ai, serv) 					\
do { 								\
	/* external reference: error and label free */ 		\
	error = get_port((ai), (serv), 0); 			\
	if (error != 0) 					\
		goto free; 					\
} while (/*CONSTCOND*/0)

#define GET_CANONNAME(ai, str) 					\
do { 								\
	/* external reference: pai, error and label free */ 	\
	error = get_canonname(pai, (ai), (str)); 		\
	if (error != 0) 					\
		goto free; 					\
} while (/*CONSTCOND*/0)

#define ERR(err) 						\
do { 								\
	/* external reference: error, and label bad */ 		\
	error = (err); 						\
	goto bad; 						\
	/*NOTREACHED*/ 						\
} while (/*CONSTCOND*/0)

#define MATCH_FAMILY(x, y, w) 						\
	((x) == (y) || (/*CONSTCOND*/(w) && ((x) == PF_UNSPEC || 	\
	    (y) == PF_UNSPEC)))
#define MATCH(x, y, w) 							\
	((x) == (y) || (/*CONSTCOND*/(w) && ((x) == ANY || (y) == ANY)))

const char *
gai_strerror(int ecode)
{
	if (ecode < 0 || ecode > EAI_MAX)
		ecode = EAI_MAX;
	return ai_errlist[ecode];
}

void
freeaddrinfo(struct addrinfo *ai)
{
	struct addrinfo *next;

	assert(ai != NULL);

	do {
		next = ai->ai_next;
		if (ai->ai_canonname)
			free(ai->ai_canonname);
		/* no need to free(ai->ai_addr) */
		free(ai);
		ai = next;
	} while (ai);
}

static int
str2number(const char *p)
{
	char *ep;
	unsigned long v;

	assert(p != NULL);

	if (*p == '\0')
		return -1;
	ep = NULL;
	errno = 0;
	v = strtoul(p, &ep, 10);
	if (errno == 0 && ep && *ep == '\0' && v <= UINT_MAX)
		return v;
	else
		return -1;
}

/* Determine whether IPv6 connectivity is available. */
static int
_have_ipv6() {
	/*
	 * Connect a UDP socket to an global unicast IPv6 address. This will
	 * cause no network traffic, but will fail fast if the system has no or
	 * limited IPv6 connectivity (e.g., only a link-local address).
	 */
	static const struct sockaddr_in6 sin6_test = {
		/* family, port, flow label */
		AF_INET6, 0, 0,
		/* 2000:: */
		{{{ 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }}},
		/* scope ID */
		0};
	static const struct sockaddr *sa_test = (struct sockaddr *) &sin6_test;
	int s = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (s < 0)
		return 0;
	int ret;
	do {
		ret = connect(s, sa_test, sizeof(sin6_test));
	} while (ret < 0 && errno == EINTR);
	int have_ipv6 = (ret == 0);
	do {
		ret = close(s);
	} while (ret < 0 && errno == EINTR);
	return have_ipv6;
}

int
getaddrinfo(const char *hostname, const char *servname,
    const struct addrinfo *hints, struct addrinfo **res)
{
	struct addrinfo sentinel;
	struct addrinfo *cur;
	int error = 0;
	struct addrinfo ai;
	struct addrinfo ai0;
	struct addrinfo *pai;
	const struct explore *ex;

	/* hostname is allowed to be NULL */
	/* servname is allowed to be NULL */
	/* hints is allowed to be NULL */
	assert(res != NULL);

	memset(&sentinel, 0, sizeof(sentinel));
	cur = &sentinel;
	pai = &ai;
	pai->ai_flags = 0;
	pai->ai_family = PF_UNSPEC;
	pai->ai_socktype = ANY;
	pai->ai_protocol = ANY;
	pai->ai_addrlen = 0;
	pai->ai_canonname = NULL;
	pai->ai_addr = NULL;
	pai->ai_next = NULL;

	if (hostname == NULL && servname == NULL)
		return EAI_NONAME;
	if (hints) {
		/* error check for hints */
		if (hints->ai_addrlen || hints->ai_canonname ||
		    hints->ai_addr || hints->ai_next)
			ERR(EAI_BADHINTS); /* xxx */
		if (hints->ai_flags & ~AI_MASK)
			ERR(EAI_BADFLAGS);
		switch (hints->ai_family) {
		case PF_UNSPEC:
		case PF_INET:
#ifdef INET6
		case PF_INET6:
#endif
			break;
		default:
			ERR(EAI_FAMILY);
		}
		memcpy(pai, hints, sizeof(*pai));

		/*
		 * if both socktype/protocol are specified, check if they
		 * are meaningful combination.
		 */
		if (pai->ai_socktype != ANY && pai->ai_protocol != ANY) {
			for (ex = explore; ex->e_af >= 0; ex++) {
				if (pai->ai_family != ex->e_af)
					continue;
				if (ex->e_socktype == ANY)
					continue;
				if (ex->e_protocol == ANY)
					continue;
				if (pai->ai_socktype == ex->e_socktype
				 && pai->ai_protocol != ex->e_protocol) {
					ERR(EAI_BADHINTS);
				}
			}
		}
	}

	/*
	 * check for special cases.  (1) numeric servname is disallowed if
	 * socktype/protocol are left unspecified. (2) servname is disallowed
	 * for raw and other inet{,6} sockets.
	 */
	if (MATCH_FAMILY(pai->ai_family, PF_INET, 1)
#ifdef PF_INET6
	 || MATCH_FAMILY(pai->ai_family, PF_INET6, 1)
#endif
	    ) {
		ai0 = *pai;	/* backup *pai */

		if (pai->ai_family == PF_UNSPEC) {
#ifdef PF_INET6
			pai->ai_family = PF_INET6;
#else
			pai->ai_family = PF_INET;
#endif
		}
		error = get_portmatch(pai, servname);
		if (error)
			ERR(error);

		*pai = ai0;
	}

	ai0 = *pai;

	/* NULL hostname, or numeric hostname */
	for (ex = explore; ex->e_af >= 0; ex++) {
		*pai = ai0;

		/* PF_UNSPEC entries are prepared for DNS queries only */
		if (ex->e_af == PF_UNSPEC)
			continue;

		if (!MATCH_FAMILY(pai->ai_family, ex->e_af, WILD_AF(ex)))
			continue;
		if (!MATCH(pai->ai_socktype, ex->e_socktype, WILD_SOCKTYPE(ex)))
			continue;
		if (!MATCH(pai->ai_protocol, ex->e_protocol, WILD_PROTOCOL(ex)))
			continue;

		if (pai->ai_family == PF_UNSPEC)
			pai->ai_family = ex->e_af;
		if (pai->ai_socktype == ANY && ex->e_socktype != ANY)
			pai->ai_socktype = ex->e_socktype;
		if (pai->ai_protocol == ANY && ex->e_protocol != ANY)
			pai->ai_protocol = ex->e_protocol;

		if (hostname == NULL)
			error = explore_null(pai, servname, &cur->ai_next);
		else
			error = explore_numeric_scope(pai, hostname, servname,
			    &cur->ai_next);

		if (error)
			goto free;

		while (cur->ai_next)
			cur = cur->ai_next;
	}

	/*
	 * XXX
	 * If numeric representation of AF1 can be interpreted as FQDN
	 * representation of AF2, we need to think again about the code below.
	 */
	if (sentinel.ai_next)
		goto good;

	if (hostname == NULL)
		ERR(EAI_NODATA);
	if (pai->ai_flags & AI_NUMERICHOST)
		ERR(EAI_NONAME);

	/*
	 * hostname as alphabetical name.
	 * we would like to prefer AF_INET6 than AF_INET, so we'll make a
	 * outer loop by AFs.
	 */
	for (ex = explore; ex->e_af >= 0; ex++) {
		*pai = ai0;

		/* require exact match for family field */
		if (pai->ai_family != ex->e_af)
			continue;

		if (!MATCH(pai->ai_socktype, ex->e_socktype,
				WILD_SOCKTYPE(ex))) {
			continue;
		}
		if (!MATCH(pai->ai_protocol, ex->e_protocol,
				WILD_PROTOCOL(ex))) {
			continue;
		}

		if (pai->ai_socktype == ANY && ex->e_socktype != ANY)
			pai->ai_socktype = ex->e_socktype;
		if (pai->ai_protocol == ANY && ex->e_protocol != ANY)
			pai->ai_protocol = ex->e_protocol;

		error = explore_fqdn(pai, hostname, servname,
			&cur->ai_next);

		while (cur && cur->ai_next)
			cur = cur->ai_next;
	}

	/* XXX */
	if (sentinel.ai_next)
		error = 0;

	if (error)
		goto free;
	if (error == 0) {
		if (sentinel.ai_next) {
 good:
			*res = sentinel.ai_next;
			return SUCCESS;
		} else
			error = EAI_FAIL;
	}
 free:
 bad:
	if (sentinel.ai_next)
		freeaddrinfo(sentinel.ai_next);
	*res = NULL;
	return error;
}

/*
 * FQDN hostname, DNS lookup
 */
static int
explore_fqdn(const struct addrinfo *pai, const char *hostname,
    const char *servname, struct addrinfo **res)
{
	struct addrinfo *result;
	struct addrinfo *cur;
	int error = 0;
	static const ns_dtab dtab[] = {
		NS_FILES_CB(_files_getaddrinfo, NULL)
		{ NSSRC_DNS, _dns_getaddrinfo, NULL },	/* force -DHESIOD */
		NS_NIS_CB(_yp_getaddrinfo, NULL)
		{ 0, 0, 0 }
	};

	assert(pai != NULL);
	/* hostname may be NULL */
	/* servname may be NULL */
	assert(res != NULL);

	result = NULL;

	/*
	 * if the servname does not match socktype/protocol, ignore it.
	 */
	if (get_portmatch(pai, servname) != 0)
		return 0;

	switch (nsdispatch(&result, dtab, NSDB_HOSTS, "getaddrinfo",
			default_dns_files, hostname, pai)) {
	case NS_TRYAGAIN:
		error = EAI_AGAIN;
		goto free;
	case NS_UNAVAIL:
		error = EAI_FAIL;
		goto free;
	case NS_NOTFOUND:
		error = EAI_NODATA;
		goto free;
	case NS_SUCCESS:
		error = 0;
		for (cur = result; cur; cur = cur->ai_next) {
			GET_PORT(cur, servname);
			/* canonname should be filled already */
		}
		break;
	}

	*res = result;

	return 0;

free:
	if (result)
		freeaddrinfo(result);
	return error;
}

/*
 * hostname == NULL.
 * passive socket -> anyaddr (0.0.0.0 or ::)
 * non-passive socket -> localhost (127.0.0.1 or ::1)
 */
static int
explore_null(const struct addrinfo *pai, const char *servname,
    struct addrinfo **res)
{
	int s;
	const struct afd *afd;
	struct addrinfo *cur;
	struct addrinfo sentinel;
	int error;

	assert(pai != NULL);
	/* servname may be NULL */
	assert(res != NULL);

	*res = NULL;
	sentinel.ai_next = NULL;
	cur = &sentinel;

	/*
	 * filter out AFs that are not supported by the kernel
	 * XXX errno?
	 */
	s = socket(pai->ai_family, SOCK_DGRAM, 0);
	if (s < 0) {
		if (errno != EMFILE)
			return 0;
	} else
		close(s);

	/*
	 * if the servname does not match socktype/protocol, ignore it.
	 */
	if (get_portmatch(pai, servname) != 0)
		return 0;

	afd = find_afd(pai->ai_family);
	if (afd == NULL)
		return 0;

	if (pai->ai_flags & AI_PASSIVE) {
		GET_AI(cur->ai_next, afd, afd->a_addrany);
		/* xxx meaningless?
		 * GET_CANONNAME(cur->ai_next, "anyaddr");
		 */
		GET_PORT(cur->ai_next, servname);
	} else {
		GET_AI(cur->ai_next, afd, afd->a_loopback);
		/* xxx meaningless?
		 * GET_CANONNAME(cur->ai_next, "localhost");
		 */
		GET_PORT(cur->ai_next, servname);
	}
	cur = cur->ai_next;

	*res = sentinel.ai_next;
	return 0;

free:
	if (sentinel.ai_next)
		freeaddrinfo(sentinel.ai_next);
	return error;
}

/*
 * numeric hostname
 */
static int
explore_numeric(const struct addrinfo *pai, const char *hostname,
    const char *servname, struct addrinfo **res, const char *canonname)
{
	const struct afd *afd;
	struct addrinfo *cur;
	struct addrinfo sentinel;
	int error;
	char pton[PTON_MAX];

	assert(pai != NULL);
	/* hostname may be NULL */
	/* servname may be NULL */
	assert(res != NULL);

	*res = NULL;
	sentinel.ai_next = NULL;
	cur = &sentinel;

	/*
	 * if the servname does not match socktype/protocol, ignore it.
	 */
	if (get_portmatch(pai, servname) != 0)
		return 0;

	afd = find_afd(pai->ai_family);
	if (afd == NULL)
		return 0;

	switch (afd->a_af) {
#if 0 /*X/Open spec*/
	case AF_INET:
		if (inet_aton(hostname, (struct in_addr *)pton) == 1) {
			if (pai->ai_family == afd->a_af ||
			    pai->ai_family == PF_UNSPEC /*?*/) {
				GET_AI(cur->ai_next, afd, pton);
				GET_PORT(cur->ai_next, servname);
				if ((pai->ai_flags & AI_CANONNAME)) {
					/*
					 * Set the numeric address itself as
					 * the canonical name, based on a
					 * clarification in rfc2553bis-03.
					 */
					GET_CANONNAME(cur->ai_next, canonname);
				}
				while (cur && cur->ai_next)
					cur = cur->ai_next;
			} else
				ERR(EAI_FAMILY);	/*xxx*/
		}
		break;
#endif
	default:
		if (inet_pton(afd->a_af, hostname, pton) == 1) {
			if (pai->ai_family == afd->a_af ||
			    pai->ai_family == PF_UNSPEC /*?*/) {
				GET_AI(cur->ai_next, afd, pton);
				GET_PORT(cur->ai_next, servname);
				if ((pai->ai_flags & AI_CANONNAME)) {
					/*
					 * Set the numeric address itself as
					 * the canonical name, based on a
					 * clarification in rfc2553bis-03.
					 */
					GET_CANONNAME(cur->ai_next, canonname);
				}
				while (cur->ai_next)
					cur = cur->ai_next;
			} else
				ERR(EAI_FAMILY);	/*xxx*/
		}
		break;
	}

	*res = sentinel.ai_next;
	return 0;

free:
bad:
	if (sentinel.ai_next)
		freeaddrinfo(sentinel.ai_next);
	return error;
}

/*
 * numeric hostname with scope
 */
static int
explore_numeric_scope(const struct addrinfo *pai, const char *hostname,
    const char *servname, struct addrinfo **res)
{
#if !defined(SCOPE_DELIMITER) || !defined(INET6)
	return explore_numeric(pai, hostname, servname, res, hostname);
#else
	const struct afd *afd;
	struct addrinfo *cur;
	int error;
	char *cp, *hostname2 = NULL, *scope, *addr;
	struct sockaddr_in6 *sin6;

	assert(pai != NULL);
	/* hostname may be NULL */
	/* servname may be NULL */
	assert(res != NULL);

	/*
	 * if the servname does not match socktype/protocol, ignore it.
	 */
	if (get_portmatch(pai, servname) != 0)
		return 0;

	afd = find_afd(pai->ai_family);
	if (afd == NULL)
		return 0;

	if (!afd->a_scoped)
		return explore_numeric(pai, hostname, servname, res, hostname);

	cp = strchr(hostname, SCOPE_DELIMITER);
	if (cp == NULL)
		return explore_numeric(pai, hostname, servname, res, hostname);

	/*
	 * Handle special case of <scoped_address><delimiter><scope id>
	 */
	hostname2 = strdup(hostname);
	if (hostname2 == NULL)
		return EAI_MEMORY;
	/* terminate at the delimiter */
	hostname2[cp - hostname] = '\0';
	addr = hostname2;
	scope = cp + 1;

	error = explore_numeric(pai, addr, servname, res, hostname);
	if (error == 0) {
		u_int32_t scopeid;

		for (cur = *res; cur; cur = cur->ai_next) {
			if (cur->ai_family != AF_INET6)
				continue;
			sin6 = (struct sockaddr_in6 *)(void *)cur->ai_addr;
			if (ip6_str2scopeid(scope, sin6, &scopeid) == -1) {
				free(hostname2);
				return(EAI_NODATA); /* XXX: is return OK? */
			}
			sin6->sin6_scope_id = scopeid;
		}
	}

	free(hostname2);

	return error;
#endif
}

static int
get_canonname(const struct addrinfo *pai, struct addrinfo *ai, const char *str)
{

	assert(pai != NULL);
	assert(ai != NULL);
	assert(str != NULL);

	if ((pai->ai_flags & AI_CANONNAME) != 0) {
		ai->ai_canonname = strdup(str);
		if (ai->ai_canonname == NULL)
			return EAI_MEMORY;
	}
	return 0;
}

static struct addrinfo *
get_ai(const struct addrinfo *pai, const struct afd *afd, const char *addr)
{
	char *p;
	struct addrinfo *ai;

	assert(pai != NULL);
	assert(afd != NULL);
	assert(addr != NULL);

	ai = (struct addrinfo *)malloc(sizeof(struct addrinfo)
		+ (afd->a_socklen));
	if (ai == NULL)
		return NULL;

	memcpy(ai, pai, sizeof(struct addrinfo));
	ai->ai_addr = (struct sockaddr *)(void *)(ai + 1);
	memset(ai->ai_addr, 0, (size_t)afd->a_socklen);

#ifdef HAVE_SA_LEN
	ai->ai_addr->sa_len = afd->a_socklen;
#endif

	ai->ai_addrlen = afd->a_socklen;
#if defined (__alpha__) || (defined(__i386__) && defined(_LP64)) || defined(__sparc64__)
	ai->__ai_pad0 = 0;
#endif
	ai->ai_addr->sa_family = ai->ai_family = afd->a_af;
	p = (char *)(void *)(ai->ai_addr);
	memcpy(p + afd->a_off, addr, (size_t)afd->a_addrlen);
	return ai;
}

static int
get_portmatch(const struct addrinfo *ai, const char *servname)
{

	assert(ai != NULL);
	/* servname may be NULL */

	return get_port(ai, servname, 1);
}

static int
get_port(const struct addrinfo *ai, const char *servname, int matchonly)
{
	const char *proto;
	struct servent *sp;
	int port;
	int allownumeric;

	assert(ai != NULL);
	/* servname may be NULL */

	if (servname == NULL)
		return 0;
	switch (ai->ai_family) {
	case AF_INET:
#ifdef AF_INET6
	case AF_INET6:
#endif
		break;
	default:
		return 0;
	}

	switch (ai->ai_socktype) {
	case SOCK_RAW:
		return EAI_SERVICE;
	case SOCK_DGRAM:
	case SOCK_STREAM:
		allownumeric = 1;
		break;
	case ANY:
#if 1  /* ANDROID-SPECIFIC CHANGE TO MATCH GLIBC */
		allownumeric = 1;
#else
		allownumeric = 0;
#endif
		break;
	default:
		return EAI_SOCKTYPE;
	}

	port = str2number(servname);
	if (port >= 0) {
		if (!allownumeric)
			return EAI_SERVICE;
		if (port < 0 || port > 65535)
			return EAI_SERVICE;
		port = htons(port);
	} else {
		if (ai->ai_flags & AI_NUMERICSERV)
			return EAI_NONAME;

		switch (ai->ai_socktype) {
		case SOCK_DGRAM:
			proto = "udp";
			break;
		case SOCK_STREAM:
			proto = "tcp";
			break;
		default:
			proto = NULL;
			break;
		}

		if ((sp = getservbyname(servname, proto)) == NULL)
			return EAI_SERVICE;
		port = sp->s_port;
	}

	if (!matchonly) {
		switch (ai->ai_family) {
		case AF_INET:
			((struct sockaddr_in *)(void *)
			    ai->ai_addr)->sin_port = port;
			break;
#ifdef INET6
		case AF_INET6:
			((struct sockaddr_in6 *)(void *)
			    ai->ai_addr)->sin6_port = port;
			break;
#endif
		}
	}

	return 0;
}

static const struct afd *
find_afd(int af)
{
	const struct afd *afd;

	if (af == PF_UNSPEC)
		return NULL;
	for (afd = afdl; afd->a_af; afd++) {
		if (afd->a_af == af)
			return afd;
	}
	return NULL;
}

#ifdef INET6
/* convert a string to a scope identifier. XXX: IPv6 specific */
static int
ip6_str2scopeid(char *scope, struct sockaddr_in6 *sin6, u_int32_t *scopeid)
{
	u_long lscopeid;
	struct in6_addr *a6;
	char *ep;

	assert(scope != NULL);
	assert(sin6 != NULL);
	assert(scopeid != NULL);

	a6 = &sin6->sin6_addr;

	/* empty scopeid portion is invalid */
	if (*scope == '\0')
		return -1;

	if (IN6_IS_ADDR_LINKLOCAL(a6) || IN6_IS_ADDR_MC_LINKLOCAL(a6)) {
		/*
		 * We currently assume a one-to-one mapping between links
		 * and interfaces, so we simply use interface indices for
		 * like-local scopes.
		 */
		*scopeid = if_nametoindex(scope);
		if (*scopeid == 0)
			goto trynumeric;
		return 0;
	}

	/* still unclear about literal, allow numeric only - placeholder */
	if (IN6_IS_ADDR_SITELOCAL(a6) || IN6_IS_ADDR_MC_SITELOCAL(a6))
		goto trynumeric;
	if (IN6_IS_ADDR_MC_ORGLOCAL(a6))
		goto trynumeric;
	else
		goto trynumeric;	/* global */

	/* try to convert to a numeric id as a last resort */
  trynumeric:
	errno = 0;
	lscopeid = strtoul(scope, &ep, 10);
	*scopeid = (u_int32_t)(lscopeid & 0xffffffffUL);
	if (errno == 0 && ep && *ep == '\0' && *scopeid == lscopeid)
		return 0;
	else
		return -1;
}
#endif

/* code duplicate with gethnamaddr.c */

static const char AskedForGot[] =
	"gethostby*.getanswer: asked for \"%s\", got \"%s\"";

static struct addrinfo *
getanswer(const querybuf *answer, int anslen, const char *qname, int qtype,
    const struct addrinfo *pai)
{
	struct addrinfo sentinel, *cur;
	struct addrinfo ai;
	const struct afd *afd;
	char *canonname;
	const HEADER *hp;
	const u_char *cp;
	int n;
	const u_char *eom;
	char *bp, *ep;
	int type, class, ancount, qdcount;
	int haveanswer, had_error;
	char tbuf[MAXDNAME];
	int (*name_ok) (const char *);
	char hostbuf[8*1024];

	assert(answer != NULL);
	assert(qname != NULL);
	assert(pai != NULL);

	memset(&sentinel, 0, sizeof(sentinel));
	cur = &sentinel;

	canonname = NULL;
	eom = answer->buf + anslen;
	switch (qtype) {
	case T_A:
	case T_AAAA:
	case T_ANY:	/*use T_ANY only for T_A/T_AAAA lookup*/
		name_ok = res_hnok;
		break;
	default:
		return NULL;	/* XXX should be abort(); */
	}
	/*
	 * find first satisfactory answer
	 */
	hp = &answer->hdr;
	ancount = ntohs(hp->ancount);
	qdcount = ntohs(hp->qdcount);
	bp = hostbuf;
	ep = hostbuf + sizeof hostbuf;
	cp = answer->buf + HFIXEDSZ;
	if (qdcount != 1) {
		h_errno = NO_RECOVERY;
		return (NULL);
	}
	n = dn_expand(answer->buf, eom, cp, bp, ep - bp);
	if ((n < 0) || !(*name_ok)(bp)) {
		h_errno = NO_RECOVERY;
		return (NULL);
	}
	cp += n + QFIXEDSZ;
	if (qtype == T_A || qtype == T_AAAA || qtype == T_ANY) {
		/* res_send() has already verified that the query name is the
		 * same as the one we sent; this just gets the expanded name
		 * (i.e., with the succeeding search-domain tacked on).
		 */
		n = strlen(bp) + 1;		/* for the \0 */
		if (n >= MAXHOSTNAMELEN) {
			h_errno = NO_RECOVERY;
			return (NULL);
		}
		canonname = bp;
		bp += n;
		/* The qname can be abbreviated, but h_name is now absolute. */
		qname = canonname;
	}
	haveanswer = 0;
	had_error = 0;
	while (ancount-- > 0 && cp < eom && !had_error) {
		n = dn_expand(answer->buf, eom, cp, bp, ep - bp);
		if ((n < 0) || !(*name_ok)(bp)) {
			had_error++;
			continue;
		}
		cp += n;			/* name */
		type = _getshort(cp);
 		cp += INT16SZ;			/* type */
		class = _getshort(cp);
 		cp += INT16SZ + INT32SZ;	/* class, TTL */
		n = _getshort(cp);
		cp += INT16SZ;			/* len */
		if (class != C_IN) {
			/* XXX - debug? syslog? */
			cp += n;
			continue;		/* XXX - had_error++ ? */
		}
		if ((qtype == T_A || qtype == T_AAAA || qtype == T_ANY) &&
		    type == T_CNAME) {
			n = dn_expand(answer->buf, eom, cp, tbuf, sizeof tbuf);
			if ((n < 0) || !(*name_ok)(tbuf)) {
				had_error++;
				continue;
			}
			cp += n;
			/* Get canonical name. */
			n = strlen(tbuf) + 1;	/* for the \0 */
			if (n > ep - bp || n >= MAXHOSTNAMELEN) {
				had_error++;
				continue;
			}
			strlcpy(bp, tbuf, (size_t)(ep - bp));
			canonname = bp;
			bp += n;
			continue;
		}
		if (qtype == T_ANY) {
			if (!(type == T_A || type == T_AAAA)) {
				cp += n;
				continue;
			}
		} else if (type != qtype) {
			if (type != T_KEY && type != T_SIG)
				syslog(LOG_NOTICE|LOG_AUTH,
	       "gethostby*.getanswer: asked for \"%s %s %s\", got type \"%s\"",
				       qname, p_class(C_IN), p_type(qtype),
				       p_type(type));
			cp += n;
			continue;		/* XXX - had_error++ ? */
		}
		switch (type) {
		case T_A:
		case T_AAAA:
			if (strcasecmp(canonname, bp) != 0) {
				syslog(LOG_NOTICE|LOG_AUTH,
				       AskedForGot, canonname, bp);
				cp += n;
				continue;	/* XXX - had_error++ ? */
			}
			if (type == T_A && n != INADDRSZ) {
				cp += n;
				continue;
			}
			if (type == T_AAAA && n != IN6ADDRSZ) {
				cp += n;
				continue;
			}
			if (type == T_AAAA) {
				struct in6_addr in6;
				memcpy(&in6, cp, IN6ADDRSZ);
				if (IN6_IS_ADDR_V4MAPPED(&in6)) {
					cp += n;
					continue;
				}
			}
			if (!haveanswer) {
				int nn;

				canonname = bp;
				nn = strlen(bp) + 1;	/* for the \0 */
				bp += nn;
			}

			/* don't overwrite pai */
			ai = *pai;
			ai.ai_family = (type == T_A) ? AF_INET : AF_INET6;
			afd = find_afd(ai.ai_family);
			if (afd == NULL) {
				cp += n;
				continue;
			}
			cur->ai_next = get_ai(&ai, afd, (const char *)cp);
			if (cur->ai_next == NULL)
				had_error++;
			while (cur && cur->ai_next)
				cur = cur->ai_next;
			cp += n;
			break;
		default:
			abort();
		}
		if (!had_error)
			haveanswer++;
	}
	if (haveanswer) {
		if (!canonname)
			(void)get_canonname(pai, sentinel.ai_next, qname);
		else
			(void)get_canonname(pai, sentinel.ai_next, canonname);
		h_errno = NETDB_SUCCESS;
		return sentinel.ai_next;
	}

	h_errno = NO_RECOVERY;
	return NULL;
}

struct addrinfo_sort_elem {
	struct addrinfo *ai;
	int has_src_addr;
	struct sockaddr_in6 src_addr;  /* Large enough to hold IPv4 or IPv6. */
	int original_order;
};

/*ARGSUSED*/
static int
_get_scope(const struct sockaddr *addr)
{
	if (addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *)addr;
		if (IN6_IS_ADDR_MULTICAST(&addr6->sin6_addr)) {
			return IPV6_ADDR_MC_SCOPE(&addr6->sin6_addr);
		} else if (IN6_IS_ADDR_LOOPBACK(&addr6->sin6_addr) ||
			   IN6_IS_ADDR_LINKLOCAL(&addr6->sin6_addr)) {
			/*
			 * RFC 4291 section 2.5.3 says loopback is to be treated as having
			 * link-local scope.
			 */
			return IPV6_ADDR_SCOPE_LINKLOCAL;
		} else if (IN6_IS_ADDR_SITELOCAL(&addr6->sin6_addr)) {
			return IPV6_ADDR_SCOPE_SITELOCAL;
		} else {
			return IPV6_ADDR_SCOPE_GLOBAL;
		}
	} else if (addr->sa_family == AF_INET) {
		const struct sockaddr_in *addr4 = (const struct sockaddr_in *)addr;
		unsigned long int na = ntohl(addr4->sin_addr.s_addr);

		if (IN_LOOPBACK(na) ||                          /* 127.0.0.0/8 */
		    (na & 0xffff0000) == 0xa9fe0000) {          /* 169.254.0.0/16 */
			return IPV6_ADDR_SCOPE_LINKLOCAL;
		} else if ((na & 0xff000000) == 0x0a000000 ||   /* 10.0.0.0/8 */
			   (na & 0xfff00000) == 0xac100000 ||   /* 172.16.0.0/12 */
			   (na & 0xffff0000) == 0xc0a80000) {   /* 192.168.0.0/16 */
			return IPV6_ADDR_SCOPE_SITELOCAL;
		} else {
			return IPV6_ADDR_SCOPE_GLOBAL;
		}
	} else {
		/*
		 * This should never happen.
		 * Return a scope with low priority as a last resort.
		 */
		return IPV6_ADDR_SCOPE_NODELOCAL;
	}
}

/* These macros are modelled after the ones in <netinet/in6.h>. */

/* RFC 4380, section 2.6 */
#define IN6_IS_ADDR_TEREDO(a)	 \
	((*(const uint32_t *)(const void *)(&(a)->s6_addr[0]) == ntohl(0x20010000)))

/* RFC 3056, section 2. */
#define IN6_IS_ADDR_6TO4(a)	 \
	(((a)->s6_addr[0] == 0x20) && ((a)->s6_addr[1] == 0x02))

/*
 * Get the label for a given IPv4/IPv6 address.
 * RFC 3484, section 2.1, plus Teredo added in with label 5.
 */

/*ARGSUSED*/
static int
_get_label(const struct sockaddr *addr)
{
	if (addr->sa_family == AF_INET) {
		return 4;
	} else if (addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *)addr;
		if (IN6_IS_ADDR_LOOPBACK(&addr6->sin6_addr)) {
			return 0;
		} else if (IN6_IS_ADDR_V4COMPAT(&addr6->sin6_addr)) {
			return 3;
		} else if (IN6_IS_ADDR_TEREDO(&addr6->sin6_addr)) {
			return 5;
		} else if (IN6_IS_ADDR_6TO4(&addr6->sin6_addr)) {
			return 2;
		} else {
			return 1;
		}
	} else {
		/*
		 * This should never happen.
		 * Return a semi-random label as a last resort.
		 */
		return 1;
	}
}

/*
 * Get the precedence for a given IPv4/IPv6 address.
 * RFC 3484, section 2.1, plus Teredo added in with precedence 25.
 */

/*ARGSUSED*/
static int
_get_precedence(const struct sockaddr *addr)
{
	if (addr->sa_family == AF_INET) {
		return 10;
	} else if (addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *)addr;
		if (IN6_IS_ADDR_LOOPBACK(&addr6->sin6_addr)) {
			return 50;
		} else if (IN6_IS_ADDR_V4COMPAT(&addr6->sin6_addr)) {
			return 20;
		} else if (IN6_IS_ADDR_TEREDO(&addr6->sin6_addr)) {
			return 25;
		} else if (IN6_IS_ADDR_6TO4(&addr6->sin6_addr)) {
			return 30;
		} else {
			return 40;
		}
	} else {
		return 5;
	}
}

/*
 * Find number of matching initial bits between the two addresses a1 and a2.
 */

/*ARGSUSED*/
static int
_common_prefix_len(const struct in6_addr *a1, const struct in6_addr *a2)
{
	const char *p1 = (const char *)a1;
	const char *p2 = (const char *)a2;
	unsigned i;

	for (i = 0; i < sizeof(*a1); ++i) {
		int x, j;

		if (p1[i] == p2[i]) {
			continue;
		}
		x = p1[i] ^ p2[i];
		for (j = 0; j < CHAR_BIT; ++j) {
			if (x & (1 << (CHAR_BIT - 1))) {
				return i * CHAR_BIT + j;
			}
			x <<= 1;
		}
	}
	return sizeof(*a1) * CHAR_BIT;
}

/*
 * Compare two source/destination address pairs.
 * RFC 3484, section 6.
 */

/*ARGSUSED*/
static int
_rfc3484_compare(const void *ptr1, const void* ptr2)
{
	const struct addrinfo_sort_elem *a1 = (const struct addrinfo_sort_elem *)ptr1;
	const struct addrinfo_sort_elem *a2 = (const struct addrinfo_sort_elem *)ptr2;
	int scope_src1, scope_dst1, scope_match1;
	int scope_src2, scope_dst2, scope_match2;
	int label_src1, label_dst1, label_match1;
	int label_src2, label_dst2, label_match2;
	int precedence1, precedence2;
	int prefixlen1, prefixlen2;

	/* Rule 1: Avoid unusable destinations. */
	if (a1->has_src_addr != a2->has_src_addr) {
		return a2->has_src_addr - a1->has_src_addr;
	}

	/* Rule 2: Prefer matching scope. */
	scope_src1 = _get_scope((const struct sockaddr *)&a1->src_addr);
	scope_dst1 = _get_scope(a1->ai->ai_addr);
	scope_match1 = (scope_src1 == scope_dst1);

	scope_src2 = _get_scope((const struct sockaddr *)&a2->src_addr);
	scope_dst2 = _get_scope(a2->ai->ai_addr);
	scope_match2 = (scope_src2 == scope_dst2);

	if (scope_match1 != scope_match2) {
		return scope_match2 - scope_match1;
	}

	/*
	 * Rule 3: Avoid deprecated addresses.
	 * TODO(sesse): We don't currently have a good way of finding this.
	 */

	/*
	 * Rule 4: Prefer home addresses.
	 * TODO(sesse): We don't currently have a good way of finding this.
	 */

	/* Rule 5: Prefer matching label. */
	label_src1 = _get_label((const struct sockaddr *)&a1->src_addr);
	label_dst1 = _get_label(a1->ai->ai_addr);
	label_match1 = (label_src1 == label_dst1);

	label_src2 = _get_label((const struct sockaddr *)&a2->src_addr);
	label_dst2 = _get_label(a2->ai->ai_addr);
	label_match2 = (label_src2 == label_dst2);

	if (label_match1 != label_match2) {
		return label_match2 - label_match1;
	}

	/* Rule 6: Prefer higher precedence. */
	precedence1 = _get_precedence(a1->ai->ai_addr);
	precedence2 = _get_precedence(a2->ai->ai_addr);
	if (precedence1 != precedence2) {
		return precedence2 - precedence1;
	}

	/*
	 * Rule 7: Prefer native transport.
	 * TODO(sesse): We don't currently have a good way of finding this.
	 */

	/* Rule 8: Prefer smaller scope. */
	if (scope_dst1 != scope_dst2) {
		return scope_dst1 - scope_dst2;
	}

	/*
	 * Rule 9: Use longest matching prefix.
         * We implement this for IPv6 only, as the rules in RFC 3484 don't seem
         * to work very well directly applied to IPv4. (glibc uses information from
         * the routing table for a custom IPv4 implementation here.)
	 */
	if (a1->has_src_addr && a1->ai->ai_addr->sa_family == AF_INET6 &&
	    a2->has_src_addr && a2->ai->ai_addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *a1_src = (const struct sockaddr_in6 *)&a1->src_addr;
		const struct sockaddr_in6 *a1_dst = (const struct sockaddr_in6 *)a1->ai->ai_addr;
		const struct sockaddr_in6 *a2_src = (const struct sockaddr_in6 *)&a2->src_addr;
		const struct sockaddr_in6 *a2_dst = (const struct sockaddr_in6 *)a2->ai->ai_addr;
		prefixlen1 = _common_prefix_len(&a1_src->sin6_addr, &a1_dst->sin6_addr);
		prefixlen2 = _common_prefix_len(&a2_src->sin6_addr, &a2_dst->sin6_addr);
		if (prefixlen1 != prefixlen2) {
			return prefixlen2 - prefixlen1;
		}
	}

	/*
	 * Rule 10: Leave the order unchanged.
	 * We need this since qsort() is not necessarily stable.
	 */
	return a1->original_order - a2->original_order;
}

/*
 * Find the source address that will be used if trying to connect to the given
 * address. src_addr must be large enough to hold a struct sockaddr_in6.
 *
 * Returns 1 if a source address was found, 0 if the address is unreachable,
 * and -1 if a fatal error occurred. If 0 or 1, the contents of src_addr are
 * undefined.
 */

/*ARGSUSED*/
static int
_find_src_addr(const struct sockaddr *addr, struct sockaddr *src_addr)
{
	int sock;
	int ret;
	socklen_t len;

	switch (addr->sa_family) {
	case AF_INET:
		len = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		len = sizeof(struct sockaddr_in6);
		break;
	default:
		/* No known usable source address for non-INET families. */
		return 0;
	}

	sock = socket(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == -1) {
		if (errno == EAFNOSUPPORT) {
			return 0;
		} else {
			return -1;
		}
	}

	do {
		ret = connect(sock, addr, len);
	} while (ret == -1 && errno == EINTR);

	if (ret == -1) {
		close(sock);
		return 0;
	}

	if (getsockname(sock, src_addr, &len) == -1) {
		close(sock);
		return -1;
	}
	close(sock);
	return 1;
}

/*
 * Sort the linked list starting at sentinel->ai_next in RFC3484 order.
 * Will leave the list unchanged if an error occurs.
 */

/*ARGSUSED*/
static void
_rfc3484_sort(struct addrinfo *list_sentinel)
{
	struct addrinfo *cur;
	int nelem = 0, i;
	struct addrinfo_sort_elem *elems;

	cur = list_sentinel->ai_next;
	while (cur) {
		++nelem;
		cur = cur->ai_next;
	}

	elems = (struct addrinfo_sort_elem *)malloc(nelem * sizeof(struct addrinfo_sort_elem));
	if (elems == NULL) {
		goto error;
	}

	/*
	 * Convert the linked list to an array that also contains the candidate
	 * source address for each destination address.
	 */
	for (i = 0, cur = list_sentinel->ai_next; i < nelem; ++i, cur = cur->ai_next) {
		int has_src_addr;
		assert(cur != NULL);
		elems[i].ai = cur;
		elems[i].original_order = i;

		has_src_addr = _find_src_addr(cur->ai_addr, (struct sockaddr *)&elems[i].src_addr);
		if (has_src_addr == -1) {
			goto error;
		}
		elems[i].has_src_addr = has_src_addr;
	}

	/* Sort the addresses, and rearrange the linked list so it matches the sorted order. */
	qsort((void *)elems, nelem, sizeof(struct addrinfo_sort_elem), _rfc3484_compare);

	list_sentinel->ai_next = elems[0].ai;
	for (i = 0; i < nelem - 1; ++i) {
		elems[i].ai->ai_next = elems[i + 1].ai;
	}
	elems[nelem - 1].ai->ai_next = NULL;

error:
	free(elems);
}

/*ARGSUSED*/
static int
_dns_getaddrinfo(void *rv, void	*cb_data, va_list ap)
{
	struct addrinfo *ai;
	querybuf *buf, *buf2;
	const char *name;
	const struct addrinfo *pai;
	struct addrinfo sentinel, *cur;
	struct res_target q, q2;
	res_state res;

	name = va_arg(ap, char *);
	pai = va_arg(ap, const struct addrinfo *);
	//fprintf(stderr, "_dns_getaddrinfo() name = '%s'\n", name);

	memset(&q, 0, sizeof(q));
	memset(&q2, 0, sizeof(q2));
	memset(&sentinel, 0, sizeof(sentinel));
	cur = &sentinel;

	buf = malloc(sizeof(*buf));
	if (buf == NULL) {
		h_errno = NETDB_INTERNAL;
		return NS_NOTFOUND;
	}
	buf2 = malloc(sizeof(*buf2));
	if (buf2 == NULL) {
		free(buf);
		h_errno = NETDB_INTERNAL;
		return NS_NOTFOUND;
	}

	switch (pai->ai_family) {
	case AF_UNSPEC:
		/* prefer IPv6 */
		q.name = name;
		q.qclass = C_IN;
		q.answer = buf->buf;
		q.anslen = sizeof(buf->buf);
		/* If AI_ADDRCONFIG, lookup IPv6 only if we have connectivity */
		if (!(pai->ai_flags & AI_ADDRCONFIG) || _have_ipv6()) {
			q.qtype = T_AAAA;
			q.next = &q2;
			q2.name = name;
			q2.qclass = C_IN;
			q2.qtype = T_A;
			q2.answer = buf2->buf;
			q2.anslen = sizeof(buf2->buf);
		} else {
			q.qtype = T_A;
		}
		break;
	case AF_INET:
		q.name = name;
		q.qclass = C_IN;
		q.qtype = T_A;
		q.answer = buf->buf;
		q.anslen = sizeof(buf->buf);
		break;
	case AF_INET6:
		q.name = name;
		q.qclass = C_IN;
		q.qtype = T_AAAA;
		q.answer = buf->buf;
		q.anslen = sizeof(buf->buf);
		break;
	default:
		free(buf);
		free(buf2);
		return NS_UNAVAIL;
	}

	res = __res_get_state();
	if (res == NULL) {
		free(buf);
		free(buf2);
		return NS_NOTFOUND;
	}

	if (res_searchN(name, &q, res) < 0) {
		__res_put_state(res);
		free(buf);
		free(buf2);
		return NS_NOTFOUND;
	}
	ai = getanswer(buf, q.n, q.name, q.qtype, pai);
	if (ai) {
		cur->ai_next = ai;
		while (cur && cur->ai_next)
			cur = cur->ai_next;
	}
	if (q.next) {
		ai = getanswer(buf2, q2.n, q2.name, q2.qtype, pai);
		if (ai)
			cur->ai_next = ai;
	}
	free(buf);
	free(buf2);
	if (sentinel.ai_next == NULL) {
		__res_put_state(res);
		switch (h_errno) {
		case HOST_NOT_FOUND:
			return NS_NOTFOUND;
		case TRY_AGAIN:
			return NS_TRYAGAIN;
		default:
			return NS_UNAVAIL;
		}
	}

	_rfc3484_sort(&sentinel);

	__res_put_state(res);

	*((struct addrinfo **)rv) = sentinel.ai_next;
	return NS_SUCCESS;
}

static void
_sethtent(FILE **hostf)
{

	if (!*hostf)
		*hostf = fopen(_PATH_HOSTS, "r" );
	else
		rewind(*hostf);
}

static void
_endhtent(FILE **hostf)
{

	if (*hostf) {
		(void) fclose(*hostf);
		*hostf = NULL;
	}
}

static struct addrinfo *
_gethtent(FILE **hostf, const char *name, const struct addrinfo *pai)
{
	char *p;
	char *cp, *tname, *cname;
	struct addrinfo hints, *res0, *res;
	int error;
	const char *addr;
	char hostbuf[8*1024];

//	fprintf(stderr, "_gethtent() name = '%s'\n", name);
	assert(name != NULL);
	assert(pai != NULL);

	if (!*hostf && !(*hostf = fopen(_PATH_HOSTS, "r" )))
		return (NULL);
 again:
	if (!(p = fgets(hostbuf, sizeof hostbuf, *hostf)))
		return (NULL);
	if (*p == '#')
		goto again;
	if (!(cp = strpbrk(p, "#\n")))
		goto again;
	*cp = '\0';
	if (!(cp = strpbrk(p, " \t")))
		goto again;
	*cp++ = '\0';
	addr = p;
	/* if this is not something we're looking for, skip it. */
	cname = NULL;
	while (cp && *cp) {
		if (*cp == ' ' || *cp == '\t') {
			cp++;
			continue;
		}
		if (!cname)
			cname = cp;
		tname = cp;
		if ((cp = strpbrk(cp, " \t")) != NULL)
			*cp++ = '\0';
//		fprintf(stderr, "\ttname = '%s'", tname);
		if (strcasecmp(name, tname) == 0)
			goto found;
	}
	goto again;

found:
	hints = *pai;
	hints.ai_flags = AI_NUMERICHOST;
	error = getaddrinfo(addr, NULL, &hints, &res0);
	if (error)
		goto again;
	for (res = res0; res; res = res->ai_next) {
		/* cover it up */
		res->ai_flags = pai->ai_flags;

		if (pai->ai_flags & AI_CANONNAME) {
			if (get_canonname(pai, res, cname) != 0) {
				freeaddrinfo(res0);
				goto again;
			}
		}
	}
	return res0;
}

/*ARGSUSED*/
static int
_files_getaddrinfo(void *rv, void *cb_data, va_list ap)
{
	const char *name;
	const struct addrinfo *pai;
	struct addrinfo sentinel, *cur;
	struct addrinfo *p;
	FILE *hostf = NULL;

	name = va_arg(ap, char *);
	pai = va_arg(ap, struct addrinfo *);

//	fprintf(stderr, "_files_getaddrinfo() name = '%s'\n", name);
	memset(&sentinel, 0, sizeof(sentinel));
	cur = &sentinel;

	_sethtent(&hostf);
	while ((p = _gethtent(&hostf, name, pai)) != NULL) {
		cur->ai_next = p;
		while (cur && cur->ai_next)
			cur = cur->ai_next;
	}
	_endhtent(&hostf);

	*((struct addrinfo **)rv) = sentinel.ai_next;
	if (sentinel.ai_next == NULL)
		return NS_NOTFOUND;
	return NS_SUCCESS;
}

/* resolver logic */

/*
 * Formulate a normal query, send, and await answer.
 * Returned answer is placed in supplied buffer "answer".
 * Perform preliminary check of answer, returning success only
 * if no error is indicated and the answer count is nonzero.
 * Return the size of the response on success, -1 on error.
 * Error number is left in h_errno.
 *
 * Caller must parse answer and determine whether it answers the question.
 */
static int
res_queryN(const char *name, /* domain name */ struct res_target *target,
    res_state res)
{
	u_char buf[MAXPACKET];
	HEADER *hp;
	int n;
	struct res_target *t;
	int rcode;
	int ancount;

	assert(name != NULL);
	/* XXX: target may be NULL??? */

	rcode = NOERROR;
	ancount = 0;

	for (t = target; t; t = t->next) {
		int class, type;
		u_char *answer;
		int anslen;

		hp = (HEADER *)(void *)t->answer;
		hp->rcode = NOERROR;	/* default */

		/* make it easier... */
		class = t->qclass;
		type = t->qtype;
		answer = t->answer;
		anslen = t->anslen;
#ifdef DEBUG
		if (res->options & RES_DEBUG)
			printf(";; res_nquery(%s, %d, %d)\n", name, class, type);
#endif

		n = res_nmkquery(res, QUERY, name, class, type, NULL, 0, NULL,
		    buf, sizeof(buf));
#ifdef RES_USE_EDNS0
		if (n > 0 && (res->options & RES_USE_EDNS0) != 0)
			n = res_nopt(res, n, buf, sizeof(buf), anslen);
#endif
		if (n <= 0) {
#ifdef DEBUG
			if (res->options & RES_DEBUG)
				printf(";; res_nquery: mkquery failed\n");
#endif
			h_errno = NO_RECOVERY;
			return n;
		}
		n = res_nsend(res, buf, n, answer, anslen);
#if 0
		if (n < 0) {
#ifdef DEBUG
			if (res->options & RES_DEBUG)
				printf(";; res_query: send error\n");
#endif
			h_errno = TRY_AGAIN;
			return n;
		}
#endif

		if (n < 0 || hp->rcode != NOERROR || ntohs(hp->ancount) == 0) {
			rcode = hp->rcode;	/* record most recent error */
#ifdef DEBUG
			if (res->options & RES_DEBUG)
				printf(";; rcode = %u, ancount=%u\n", hp->rcode,
				    ntohs(hp->ancount));
#endif
			continue;
		}

		ancount += ntohs(hp->ancount);

		t->n = n;
	}

	if (ancount == 0) {
		switch (rcode) {
		case NXDOMAIN:
			h_errno = HOST_NOT_FOUND;
			break;
		case SERVFAIL:
			h_errno = TRY_AGAIN;
			break;
		case NOERROR:
			h_errno = NO_DATA;
			break;
		case FORMERR:
		case NOTIMP:
		case REFUSED:
		default:
			h_errno = NO_RECOVERY;
			break;
		}
		return -1;
	}
	return ancount;
}

/*
 * Formulate a normal query, send, and retrieve answer in supplied buffer.
 * Return the size of the response on success, -1 on error.
 * If enabled, implement search rules until answer or unrecoverable failure
 * is detected.  Error code, if any, is left in h_errno.
 */
static int
res_searchN(const char *name, struct res_target *target, res_state res)
{
	const char *cp, * const *domain;
	HEADER *hp;
	u_int dots;
	int trailing_dot, ret, saved_herrno;
	int got_nodata = 0, got_servfail = 0, tried_as_is = 0;

	assert(name != NULL);
	assert(target != NULL);

	hp = (HEADER *)(void *)target->answer;	/*XXX*/

	errno = 0;
	h_errno = HOST_NOT_FOUND;	/* default, if we never query */
	dots = 0;
	for (cp = name; *cp; cp++)
		dots += (*cp == '.');
	trailing_dot = 0;
	if (cp > name && *--cp == '.')
		trailing_dot++;


        //fprintf(stderr, "res_searchN() name = '%s'\n", name);

	/*
	 * if there aren't any dots, it could be a user-level alias
	 */
	if (!dots && (cp = __hostalias(name)) != NULL) {
		ret = res_queryN(cp, target, res);
		return ret;
	}

	/*
	 * If there are dots in the name already, let's just give it a try
	 * 'as is'.  The threshold can be set with the "ndots" option.
	 */
	saved_herrno = -1;
	if (dots >= res->ndots) {
		ret = res_querydomainN(name, NULL, target, res);
		if (ret > 0)
			return (ret);
		saved_herrno = h_errno;
		tried_as_is++;
	}

	/*
	 * We do at least one level of search if
	 *	- there is no dot and RES_DEFNAME is set, or
	 *	- there is at least one dot, there is no trailing dot,
	 *	  and RES_DNSRCH is set.
	 */
	if ((!dots && (res->options & RES_DEFNAMES)) ||
	    (dots && !trailing_dot && (res->options & RES_DNSRCH))) {
		int done = 0;

		for (domain = (const char * const *)res->dnsrch;
		   *domain && !done;
		   domain++) {

			ret = res_querydomainN(name, *domain, target, res);
			if (ret > 0)
				return ret;

			/*
			 * If no server present, give up.
			 * If name isn't found in this domain,
			 * keep trying higher domains in the search list
			 * (if that's enabled).
			 * On a NO_DATA error, keep trying, otherwise
			 * a wildcard entry of another type could keep us
			 * from finding this entry higher in the domain.
			 * If we get some other error (negative answer or
			 * server failure), then stop searching up,
			 * but try the input name below in case it's
			 * fully-qualified.
			 */
			if (errno == ECONNREFUSED) {
				h_errno = TRY_AGAIN;
				return -1;
			}

			switch (h_errno) {
			case NO_DATA:
				got_nodata++;
				/* FALLTHROUGH */
			case HOST_NOT_FOUND:
				/* keep trying */
				break;
			case TRY_AGAIN:
				if (hp->rcode == SERVFAIL) {
					/* try next search element, if any */
					got_servfail++;
					break;
				}
				/* FALLTHROUGH */
			default:
				/* anything else implies that we're done */
				done++;
			}
			/*
			 * if we got here for some reason other than DNSRCH,
			 * we only wanted one iteration of the loop, so stop.
			 */
			if (!(res->options & RES_DNSRCH))
			        done++;
		}
	}

	/*
	 * if we have not already tried the name "as is", do that now.
	 * note that we do this regardless of how many dots were in the
	 * name or whether it ends with a dot.
	 */
	if (!tried_as_is) {
		ret = res_querydomainN(name, NULL, target, res);
		if (ret > 0)
			return ret;
	}

	/*
	 * if we got here, we didn't satisfy the search.
	 * if we did an initial full query, return that query's h_errno
	 * (note that we wouldn't be here if that query had succeeded).
	 * else if we ever got a nodata, send that back as the reason.
	 * else send back meaningless h_errno, that being the one from
	 * the last DNSRCH we did.
	 */
	if (saved_herrno != -1)
		h_errno = saved_herrno;
	else if (got_nodata)
		h_errno = NO_DATA;
	else if (got_servfail)
		h_errno = TRY_AGAIN;
	return -1;
}

/*
 * Perform a call on res_query on the concatenation of name and domain,
 * removing a trailing dot from name if domain is NULL.
 */
static int
res_querydomainN(const char *name, const char *domain,
    struct res_target *target, res_state res)
{
	char nbuf[MAXDNAME];
	const char *longname = nbuf;
	size_t n, d;

	assert(name != NULL);
	/* XXX: target may be NULL??? */

#ifdef DEBUG
	if (res->options & RES_DEBUG)
		printf(";; res_querydomain(%s, %s)\n",
			name, domain?domain:"<Nil>");
#endif
	if (domain == NULL) {
		/*
		 * Check for trailing '.';
		 * copy without '.' if present.
		 */
		n = strlen(name);
		if (n + 1 > sizeof(nbuf)) {
			h_errno = NO_RECOVERY;
			return -1;
		}
		if (n > 0 && name[--n] == '.') {
			strncpy(nbuf, name, n);
			nbuf[n] = '\0';
		} else
			longname = name;
	} else {
		n = strlen(name);
		d = strlen(domain);
		if (n + 1 + d + 1 > sizeof(nbuf)) {
			h_errno = NO_RECOVERY;
			return -1;
		}
		snprintf(nbuf, sizeof(nbuf), "%s.%s", name, domain);
	}
	return res_queryN(longname, target, res);
}
