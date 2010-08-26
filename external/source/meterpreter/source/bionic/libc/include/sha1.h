/*	$NetBSD: sha1.h,v 1.13 2005/12/26 18:41:36 perry Exp $	*/

/*
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 */

#ifndef _SYS_SHA1_H_
#define	_SYS_SHA1_H_

#include <sys/cdefs.h>
#include <sys/types.h>

#define SHA1_DIGEST_LENGTH		20
#define SHA1_DIGEST_STRING_LENGTH	41

typedef struct {
	uint32_t state[5];
	uint32_t count[2];
	u_char buffer[64];
} SHA1_CTX;

__BEGIN_DECLS
void	SHA1Transform(uint32_t[5], const u_char[64]);
void	SHA1Init(SHA1_CTX *);
void	SHA1Update(SHA1_CTX *, const u_char *, u_int);
void	SHA1Final(u_char[SHA1_DIGEST_LENGTH], SHA1_CTX *);
__END_DECLS

#endif /* _SYS_SHA1_H_ */
