/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef _RESOLV_CACHE_H_
#define _RESOLV_CACHE_H_

struct resolv_cache;  /* forward */

/* get cache instance, can be NULL if cache is disabled
 * (e.g. through an environment variable) */
extern struct resolv_cache*  __get_res_cache(void);

/* this gets called everytime we detect some changes in the DNS configuration
 * and will flush the cache */
extern void   _resolv_cache_reset( unsigned  generation );

typedef enum {
    RESOLV_CACHE_UNSUPPORTED,  /* the cache can't handle that kind of queries */
                               /* or the answer buffer is too small */
    RESOLV_CACHE_NOTFOUND,     /* the cache doesn't know about this query */
    RESOLV_CACHE_FOUND         /* the cache found the answer */
} ResolvCacheStatus;

extern ResolvCacheStatus
_resolv_cache_lookup( struct resolv_cache*  cache,
                      const void*           query,
                      int                   querylen,
                      void*                 answer,
                      int                   answersize,
                      int                  *answerlen );

/* add a (query,answer) to the cache, only call if _resolv_cache_lookup
 * did return RESOLV_CACHE_NOTFOUND
 */
extern void
_resolv_cache_add( struct resolv_cache*  cache,
                   const void*           query,
                   int                   querylen,
                   const void*           answer,
                   int                   answerlen );

#endif /* _RESOLV_CACHE_H_ */
