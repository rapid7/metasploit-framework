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

#include "resolv_cache.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "pthread.h"

/* This code implements a small and *simple* DNS resolver cache.
 *
 * It is only used to cache DNS answers for a maximum of CONFIG_SECONDS seconds
 * in order to reduce DNS traffic. It is not supposed to be a full DNS cache,
 * since we plan to implement that in the future in a dedicated process running
 * on the system.
 *
 * Note that its design is kept simple very intentionally, i.e.:
 *
 *  - it takes raw DNS query packet data as input, and returns raw DNS
 *    answer packet data as output
 *
 *    (this means that two similar queries that encode the DNS name
 *     differently will be treated distinctly).
 *
 *  - the TTLs of answer RRs are ignored. our DNS resolver library does not use
 *    them anyway, but it means that records with a TTL smaller than
 *    CONFIG_SECONDS will be kept in the cache anyway.
 *
 *    this is bad, but we absolutely want to avoid parsing the answer packets
 *    (and should be solved by the later full DNS cache process).
 *
 *  - the implementation is just a (query-data) => (answer-data) hash table
 *    with a trivial least-recently-used expiration policy.
 *
 * Doing this keeps the code simple and avoids to deal with a lot of things
 * that a full DNS cache is expected to do.
 *
 * The API is also very simple:
 *
 *   - the client calls _resolv_cache_get() to obtain a handle to the cache.
 *     this will initialize the cache on first usage. the result can be NULL
 *     if the cache is disabled.
 *
 *   - the client calls _resolv_cache_lookup() before performing a query
 *
 *     if the function returns RESOLV_CACHE_FOUND, a copy of the answer data
 *     has been copied into the client-provided answer buffer.
 *
 *     if the function returns RESOLV_CACHE_NOTFOUND, the client should perform
 *     a request normally, *then* call _resolv_cache_add() to add the received
 *     answer to the cache.
 *
 *     if the function returns RESOLV_CACHE_UNSUPPORTED, the client should
 *     perform a request normally, and *not* call _resolv_cache_add()
 *
 *     note that RESOLV_CACHE_UNSUPPORTED is also returned if the answer buffer
 *     is too short to accomodate the cached result.
 *
 *  - when network settings change, the cache must be flushed since the list
 *    of DNS servers probably changed. this is done by calling
 *    _resolv_cache_reset()
 *
 *    the parameter to this function must be an ever-increasing generation
 *    number corresponding to the current network settings state.
 *
 *    This is done because several threads could detect the same network
 *    settings change (but at different times) and will all end up calling the
 *    same function. Comparing with the last used generation number ensures
 *    that the cache is only flushed once per network change.
 */

/* the name of an environment variable that will be checked the first time
 * this code is called if its value is "0", then the resolver cache is
 * disabled.
 */
#define  CONFIG_ENV  "BIONIC_DNSCACHE"

/* entries older than CONFIG_SECONDS seconds are always discarded.
 */
#define  CONFIG_SECONDS    (60*10)    /* 10 minutes */

/* maximum number of entries kept in the cache. This value has been
 * determined by browsing through various sites and counting the number
 * of corresponding requests. Keep in mind that our framework is currently
 * performing two requests per name lookup (one for IPv4, the other for IPv6)
 *
 *    www.google.com      4
 *    www.ysearch.com     6
 *    www.amazon.com      8
 *    www.nytimes.com     22
 *    www.espn.com        28
 *    www.msn.com         28
 *    www.lemonde.fr      35
 *
 * (determined in 2009-2-17 from Paris, France, results may vary depending
 *  on location)
 *
 * most high-level websites use lots of media/ad servers with different names
 * but these are generally reused when browsing through the site.
 *
 * As such, a valud of 64 should be relatively conformtable at the moment.
 */
#define  CONFIG_MAX_ENTRIES    64

/****************************************************************************/
/****************************************************************************/
/*****                                                                  *****/
/*****                                                                  *****/
/*****                                                                  *****/
/****************************************************************************/
/****************************************************************************/

/* set to 1 to debug cache operations */
#define  DEBUG       0

/* set to 1 to debug query data */
#define  DEBUG_DATA  0

#if DEBUG
#  include <logd.h>
#  define  XLOG(...)   \
    __libc_android_log_print(ANDROID_LOG_DEBUG,"libc",__VA_ARGS__)

#include <stdio.h>
#include <stdarg.h>

/** BOUNDED BUFFER FORMATTING
 **/

/* technical note:
 *
 *   the following debugging routines are used to append data to a bounded
 *   buffer they take two parameters that are:
 *
 *   - p : a pointer to the current cursor position in the buffer
 *         this value is initially set to the buffer's address.
 *
 *   - end : the address of the buffer's limit, i.e. of the first byte
 *           after the buffer. this address should never be touched.
 *
 *           IMPORTANT: it is assumed that end > buffer_address, i.e.
 *                      that the buffer is at least one byte.
 *
 *   the _bprint_() functions return the new value of 'p' after the data
 *   has been appended, and also ensure the following:
 *
 *   - the returned value will never be strictly greater than 'end'
 *
 *   - a return value equal to 'end' means that truncation occured
 *     (in which case, end[-1] will be set to 0)
 *
 *   - after returning from a _bprint_() function, the content of the buffer
 *     is always 0-terminated, even in the event of truncation.
 *
 *  these conventions allow you to call _bprint_ functions multiple times and
 *  only check for truncation at the end of the sequence, as in:
 *
 *     char  buff[1000], *p = buff, *end = p + sizeof(buff);
 *
 *     p = _bprint_c(p, end, '"');
 *     p = _bprint_s(p, end, my_string);
 *     p = _bprint_c(p, end, '"');
 *
 *     if (p >= end) {
 *        // buffer was too small
 *     }
 *
 *     printf( "%s", buff );
 */

/* add a char to a bounded buffer */
static char*
_bprint_c( char*  p, char*  end, int  c )
{
    if (p < end) {
        if (p+1 == end)
            *p++ = 0;
        else {
            *p++ = (char) c;
            *p   = 0;
        }
    }
    return p;
}

/* add a sequence of bytes to a bounded buffer */
static char*
_bprint_b( char*  p, char*  end, const char*  buf, int  len )
{
    int  avail = end - p;

    if (avail <= 0 || len <= 0)
        return p;

    if (avail > len)
        avail = len;

    memcpy( p, buf, avail );
    p += avail;

    if (p < end)
        p[0] = 0;
    else
        end[-1] = 0;

    return p;
}

/* add a string to a bounded buffer */
static char*
_bprint_s( char*  p, char*  end, const char*  str )
{
    return _bprint_b(p, end, str, strlen(str));
}

/* add a formatted string to a bounded buffer */
static char*
_bprint( char*  p, char*  end, const char*  format, ... )
{
    int      avail, n;
    va_list  args;

    avail = end - p;

    if (avail <= 0)
        return p;

    va_start(args, format);
    n = vsnprintf( p, avail, format, args);
    va_end(args);

    /* certain C libraries return -1 in case of truncation */
    if (n < 0 || n > avail)
        n = avail;

    p += n;
    /* certain C libraries do not zero-terminate in case of truncation */
    if (p == end)
        p[-1] = 0;

    return p;
}

/* add a hex value to a bounded buffer, up to 8 digits */
static char*
_bprint_hex( char*  p, char*  end, unsigned  value, int  numDigits )
{
    char   text[sizeof(unsigned)*2];
    int    nn = 0;

    while (numDigits-- > 0) {
        text[nn++] = "0123456789abcdef"[(value >> (numDigits*4)) & 15];
    }
    return _bprint_b(p, end, text, nn);
}

/* add the hexadecimal dump of some memory area to a bounded buffer */
static char*
_bprint_hexdump( char*  p, char*  end, const uint8_t*  data, int  datalen )
{
    int   lineSize = 16;

    while (datalen > 0) {
        int  avail = datalen;
        int  nn;

        if (avail > lineSize)
            avail = lineSize;

        for (nn = 0; nn < avail; nn++) {
            if (nn > 0)
                p = _bprint_c(p, end, ' ');
            p = _bprint_hex(p, end, data[nn], 2);
        }
        for ( ; nn < lineSize; nn++ ) {
            p = _bprint_s(p, end, "   ");
        }
        p = _bprint_s(p, end, "  ");

        for (nn = 0; nn < avail; nn++) {
            int  c = data[nn];

            if (c < 32 || c > 127)
                c = '.';

            p = _bprint_c(p, end, c);
        }
        p = _bprint_c(p, end, '\n');

        data    += avail;
        datalen -= avail;
    }
    return p;
}

/* dump the content of a query of packet to the log */
static void
XLOG_BYTES( const void*  base, int  len )
{
    char  buff[1024];
    char*  p = buff, *end = p + sizeof(buff);

    p = _bprint_hexdump(p, end, base, len);
    XLOG("%s",buff);
}

#else /* !DEBUG */
#  define  XLOG(...)        ((void)0)
#  define  XLOG_BYTES(a,b)  ((void)0)
#endif

static time_t
_time_now( void )
{
    struct timeval  tv;

    gettimeofday( &tv, NULL );
    return tv.tv_sec;
}

/* reminder: the general format of a DNS packet is the following:
 *
 *    HEADER  (12 bytes)
 *    QUESTION  (variable)
 *    ANSWER (variable)
 *    AUTHORITY (variable)
 *    ADDITIONNAL (variable)
 *
 * the HEADER is made of:
 *
 *   ID     : 16 : 16-bit unique query identification field
 *
 *   QR     :  1 : set to 0 for queries, and 1 for responses
 *   Opcode :  4 : set to 0 for queries
 *   AA     :  1 : set to 0 for queries
 *   TC     :  1 : truncation flag, will be set to 0 in queries
 *   RD     :  1 : recursion desired
 *
 *   RA     :  1 : recursion available (0 in queries)
 *   Z      :  3 : three reserved zero bits
 *   RCODE  :  4 : response code (always 0=NOERROR in queries)
 *
 *   QDCount: 16 : question count
 *   ANCount: 16 : Answer count (0 in queries)
 *   NSCount: 16: Authority Record count (0 in queries)
 *   ARCount: 16: Additionnal Record count (0 in queries)
 *
 * the QUESTION is made of QDCount Question Record (QRs)
 * the ANSWER is made of ANCount RRs
 * the AUTHORITY is made of NSCount RRs
 * the ADDITIONNAL is made of ARCount RRs
 *
 * Each Question Record (QR) is made of:
 *
 *   QNAME   : variable : Query DNS NAME
 *   TYPE    : 16       : type of query (A=1, PTR=12, MX=15, AAAA=28, ALL=255)
 *   CLASS   : 16       : class of query (IN=1)
 *
 * Each Resource Record (RR) is made of:
 *
 *   NAME    : variable : DNS NAME
 *   TYPE    : 16       : type of query (A=1, PTR=12, MX=15, AAAA=28, ALL=255)
 *   CLASS   : 16       : class of query (IN=1)
 *   TTL     : 32       : seconds to cache this RR (0=none)
 *   RDLENGTH: 16       : size of RDDATA in bytes
 *   RDDATA  : variable : RR data (depends on TYPE)
 *
 * Each QNAME contains a domain name encoded as a sequence of 'labels'
 * terminated by a zero. Each label has the following format:
 *
 *    LEN  : 8     : lenght of label (MUST be < 64)
 *    NAME : 8*LEN : label length (must exclude dots)
 *
 * A value of 0 in the encoding is interpreted as the 'root' domain and
 * terminates the encoding. So 'www.android.com' will be encoded as:
 *
 *   <3>www<7>android<3>com<0>
 *
 * Where <n> represents the byte with value 'n'
 *
 * Each NAME reflects the QNAME of the question, but has a slightly more
 * complex encoding in order to provide message compression. This is achieved
 * by using a 2-byte pointer, with format:
 *
 *    TYPE   : 2  : 0b11 to indicate a pointer, 0b01 and 0b10 are reserved
 *    OFFSET : 14 : offset to another part of the DNS packet
 *
 * The offset is relative to the start of the DNS packet and must point
 * A pointer terminates the encoding.
 *
 * The NAME can be encoded in one of the following formats:
 *
 *   - a sequence of simple labels terminated by 0 (like QNAMEs)
 *   - a single pointer
 *   - a sequence of simple labels terminated by a pointer
 *
 * A pointer shall always point to either a pointer of a sequence of
 * labels (which can themselves be terminated by either a 0 or a pointer)
 *
 * The expanded length of a given domain name should not exceed 255 bytes.
 *
 * NOTE: we don't parse the answer packets, so don't need to deal with NAME
 *       records, only QNAMEs.
 */

#define  DNS_HEADER_SIZE  12

#define  DNS_TYPE_A   "\00\01"   /* big-endian decimal 1 */
#define  DNS_TYPE_PTR "\00\014"  /* big-endian decimal 12 */
#define  DNS_TYPE_MX  "\00\017"  /* big-endian decimal 15 */
#define  DNS_TYPE_AAAA "\00\034" /* big-endian decimal 28 */
#define  DNS_TYPE_ALL "\00\0377" /* big-endian decimal 255 */

#define  DNS_CLASS_IN "\00\01"   /* big-endian decimal 1 */

typedef struct {
    const uint8_t*  base;
    const uint8_t*  end;
    const uint8_t*  cursor;
} DnsPacket;

static void
_dnsPacket_init( DnsPacket*  packet, const uint8_t*  buff, int  bufflen )
{
    packet->base   = buff;
    packet->end    = buff + bufflen;
    packet->cursor = buff;
}

static void
_dnsPacket_rewind( DnsPacket*  packet )
{
    packet->cursor = packet->base;
}

static void
_dnsPacket_skip( DnsPacket*  packet, int  count )
{
    const uint8_t*  p = packet->cursor + count;

    if (p > packet->end)
        p = packet->end;

    packet->cursor = p;
}

static int
_dnsPacket_readInt16( DnsPacket*  packet )
{
    const uint8_t*  p = packet->cursor;

    if (p+2 > packet->end)
        return -1;

    packet->cursor = p+2;
    return (p[0]<< 8) | p[1];
}

/** QUERY CHECKING
 **/

/* check bytes in a dns packet. returns 1 on success, 0 on failure.
 * the cursor is only advanced in the case of success
 */
static int
_dnsPacket_checkBytes( DnsPacket*  packet, int  numBytes, const void*  bytes )
{
    const uint8_t*  p = packet->cursor;

    if (p + numBytes > packet->end)
        return 0;

    if (memcmp(p, bytes, numBytes) != 0)
        return 0;

    packet->cursor = p + numBytes;
    return 1;
}

/* parse and skip a given QNAME stored in a query packet,
 * from the current cursor position. returns 1 on success,
 * or 0 for malformed data.
 */
static int
_dnsPacket_checkQName( DnsPacket*  packet )
{
    const uint8_t*  p   = packet->cursor;
    const uint8_t*  end = packet->end;

    for (;;) {
        int  c;

        if (p >= end)
            break;

        c = *p++;

        if (c == 0) {
            packet->cursor = p;
            return 1;
        }

        /* we don't expect label compression in QNAMEs */
        if (c >= 64)
            break;

        p += c;
        /* we rely on the bound check at the start
         * of the loop here */
    }
    /* malformed data */
    XLOG("malformed QNAME");
    return 0;
}

/* parse and skip a given QR stored in a packet.
 * returns 1 on success, and 0 on failure
 */
static int
_dnsPacket_checkQR( DnsPacket*  packet )
{
    int  len;

    if (!_dnsPacket_checkQName(packet))
        return 0;

    /* TYPE must be one of the things we support */
    if (!_dnsPacket_checkBytes(packet, 2, DNS_TYPE_A) &&
        !_dnsPacket_checkBytes(packet, 2, DNS_TYPE_PTR) &&
        !_dnsPacket_checkBytes(packet, 2, DNS_TYPE_MX) &&
        !_dnsPacket_checkBytes(packet, 2, DNS_TYPE_AAAA) &&
        !_dnsPacket_checkBytes(packet, 2, DNS_TYPE_ALL))
    {
        XLOG("unsupported TYPE");
        return 0;
    }
    /* CLASS must be IN */
    if (!_dnsPacket_checkBytes(packet, 2, DNS_CLASS_IN)) {
        XLOG("unsupported CLASS");
        return 0;
    }

    return 1;
}

/* check the header of a DNS Query packet, return 1 if it is one
 * type of query we can cache, or 0 otherwise
 */
static int
_dnsPacket_checkQuery( DnsPacket*  packet )
{
    const uint8_t*  p = packet->base;
    int             qdCount, anCount, dnCount, arCount;

    if (p + DNS_HEADER_SIZE > packet->end) {
        XLOG("query packet too small");
        return 0;
    }

    /* QR must be set to 0, opcode must be 0 and AA must be 0 */
    /* RA, Z, and RCODE must be 0 */
    if ((p[2] & 0xFC) != 0 || p[3] != 0) {
        XLOG("query packet flags unsupported");
        return 0;
    }

    /* Note that we ignore the TC and RD bits here for the
     * following reasons:
     *
     * - there is no point for a query packet sent to a server
     *   to have the TC bit set, but the implementation might
     *   set the bit in the query buffer for its own needs
     *   between a _resolv_cache_lookup and a
     *   _resolv_cache_add. We should not freak out if this
     *   is the case.
     *
     * - we consider that the result from a RD=0 or a RD=1
     *   query might be different, hence that the RD bit
     *   should be used to differentiate cached result.
     *
     *   this implies that RD is checked when hashing or
     *   comparing query packets, but not TC
     */

    /* ANCOUNT, DNCOUNT and ARCOUNT must be 0 */
    qdCount = (p[4] << 8) | p[5];
    anCount = (p[6] << 8) | p[7];
    dnCount = (p[8] << 8) | p[9];
    arCount = (p[10]<< 8) | p[11];

    if (anCount != 0 || dnCount != 0 || arCount != 0) {
        XLOG("query packet contains non-query records");
        return 0;
    }

    if (qdCount == 0) {
        XLOG("query packet doesn't contain query record");
        return 0;
    }

    /* Check QDCOUNT QRs */
    packet->cursor = p + DNS_HEADER_SIZE;

    for (;qdCount > 0; qdCount--)
        if (!_dnsPacket_checkQR(packet))
            return 0;

    return 1;
}

/** QUERY DEBUGGING
 **/
#if DEBUG
static char*
_dnsPacket_bprintQName(DnsPacket*  packet, char*  bp, char*  bend)
{
    const uint8_t*  p   = packet->cursor;
    const uint8_t*  end = packet->end;
    int             first = 1;

    for (;;) {
        int  c;

        if (p >= end)
            break;

        c = *p++;

        if (c == 0) {
            packet->cursor = p;
            return bp;
        }

        /* we don't expect label compression in QNAMEs */
        if (c >= 64)
            break;

        if (first)
            first = 0;
        else
            bp = _bprint_c(bp, bend, '.');

        bp = _bprint_b(bp, bend, (const char*)p, c);

        p += c;
        /* we rely on the bound check at the start
         * of the loop here */
    }
    /* malformed data */
    bp = _bprint_s(bp, bend, "<MALFORMED>");
    return bp;
}

static char*
_dnsPacket_bprintQR(DnsPacket*  packet, char*  p, char*  end)
{
#define  QQ(x)   { DNS_TYPE_##x, #x }
    static const struct { 
        const char*  typeBytes;
        const char*  typeString; 
    } qTypes[] =
    {
        QQ(A), QQ(PTR), QQ(MX), QQ(AAAA), QQ(ALL),
        { NULL, NULL }
    };
    int          nn;
    const char*  typeString = NULL;

    /* dump QNAME */
    p = _dnsPacket_bprintQName(packet, p, end);

    /* dump TYPE */
    p = _bprint_s(p, end, " (");

    for (nn = 0; qTypes[nn].typeBytes != NULL; nn++) {
        if (_dnsPacket_checkBytes(packet, 2, qTypes[nn].typeBytes)) {
            typeString = qTypes[nn].typeString;
            break;
        }
    }

    if (typeString != NULL)
        p = _bprint_s(p, end, typeString);
    else {
        int  typeCode = _dnsPacket_readInt16(packet);
        p = _bprint(p, end, "UNKNOWN-%d", typeCode);
    }

    p = _bprint_c(p, end, ')');

    /* skip CLASS */
    _dnsPacket_skip(packet, 2);
    return p;
}

/* this function assumes the packet has already been checked */
static char*
_dnsPacket_bprintQuery( DnsPacket*  packet, char*  p, char*  end )
{
    int   qdCount;

    if (packet->base[2] & 0x1) {
        p = _bprint_s(p, end, "RECURSIVE ");
    }

    _dnsPacket_skip(packet, 4);
    qdCount = _dnsPacket_readInt16(packet);
    _dnsPacket_skip(packet, 6);

    for ( ; qdCount > 0; qdCount-- ) {
        p = _dnsPacket_bprintQR(packet, p, end);
    }
    return p;
}
#endif


/** QUERY HASHING SUPPORT
 **
 ** THE FOLLOWING CODE ASSUMES THAT THE INPUT PACKET HAS ALREADY
 ** BEEN SUCCESFULLY CHECKED.
 **/

/* use 32-bit FNV hash function */
#define  FNV_MULT   16777619U
#define  FNV_BASIS  2166136261U

static unsigned
_dnsPacket_hashBytes( DnsPacket*  packet, int  numBytes, unsigned  hash )
{
    const uint8_t*  p   = packet->cursor;
    const uint8_t*  end = packet->end;

    while (numBytes > 0 && p < end) {
        hash = hash*FNV_MULT ^ *p++;
    }
    packet->cursor = p;
    return hash;
}


static unsigned
_dnsPacket_hashQName( DnsPacket*  packet, unsigned  hash )
{
    const uint8_t*  p   = packet->cursor;
    const uint8_t*  end = packet->end;

    for (;;) {
        int  c;

        if (p >= end) {  /* should not happen */
            XLOG("%s: INTERNAL_ERROR: read-overflow !!\n", __FUNCTION__);
            break;
        }

        c = *p++;

        if (c == 0)
            break;

        if (c >= 64) {
            XLOG("%s: INTERNAL_ERROR: malformed domain !!\n", __FUNCTION__);
            break;
        }
        if (p + c >= end) {
            XLOG("%s: INTERNAL_ERROR: simple label read-overflow !!\n",
                    __FUNCTION__);
            break;
        }
        while (c > 0) {
            hash = hash*FNV_MULT ^ *p++;
            c   -= 1;
        }
    }
    packet->cursor = p;
    return hash;
}

static unsigned
_dnsPacket_hashQR( DnsPacket*  packet, unsigned  hash )
{
    int   len;

    hash = _dnsPacket_hashQName(packet, hash);
    hash = _dnsPacket_hashBytes(packet, 4, hash); /* TYPE and CLASS */
    return hash;
}

static unsigned
_dnsPacket_hashQuery( DnsPacket*  packet )
{
    unsigned  hash = FNV_BASIS;
    int       count;
    _dnsPacket_rewind(packet);

    /* we ignore the TC bit for reasons explained in
     * _dnsPacket_checkQuery().
     *
     * however we hash the RD bit to differentiate
     * between answers for recursive and non-recursive
     * queries.
     */
    hash = hash*FNV_MULT ^ (packet->base[2] & 1);

    /* assume: other flags are 0 */
    _dnsPacket_skip(packet, 4);

    /* read QDCOUNT */
    count = _dnsPacket_readInt16(packet);

    /* assume: ANcount, NScount, ARcount are 0 */
    _dnsPacket_skip(packet, 6);

    /* hash QDCOUNT QRs */
    for ( ; count > 0; count-- )
        hash = _dnsPacket_hashQR(packet, hash);

    return hash;
}


/** QUERY COMPARISON
 **
 ** THE FOLLOWING CODE ASSUMES THAT THE INPUT PACKETS HAVE ALREADY
 ** BEEN SUCCESFULLY CHECKED.
 **/

static int
_dnsPacket_isEqualDomainName( DnsPacket*  pack1, DnsPacket*  pack2 )
{
    const uint8_t*  p1   = pack1->cursor;
    const uint8_t*  end1 = pack1->end;
    const uint8_t*  p2   = pack2->cursor;
    const uint8_t*  end2 = pack2->end;

    for (;;) {
        int  c1, c2;

        if (p1 >= end1 || p2 >= end2) {
            XLOG("%s: INTERNAL_ERROR: read-overflow !!\n", __FUNCTION__);
            break;
        }
        c1 = *p1++;
        c2 = *p2++;
        if (c1 != c2)
            break;

        if (c1 == 0) {
            pack1->cursor = p1;
            pack2->cursor = p2;
            return 1;
        }
        if (c1 >= 64) {
            XLOG("%s: INTERNAL_ERROR: malformed domain !!\n", __FUNCTION__);
            break;
        }
        if ((p1+c1 > end1) || (p2+c1 > end2)) {
            XLOG("%s: INTERNAL_ERROR: simple label read-overflow !!\n",
                    __FUNCTION__);
            break;
        }
        if (memcmp(p1, p2, c1) != 0)
            break;
        p1 += c1;
        p2 += c1;
        /* we rely on the bound checks at the start of the loop */
    }
    /* not the same, or one is malformed */
    XLOG("different DN");
    return 0;
}

static int
_dnsPacket_isEqualBytes( DnsPacket*  pack1, DnsPacket*  pack2, int  numBytes )
{
    const uint8_t*  p1 = pack1->cursor;
    const uint8_t*  p2 = pack2->cursor;

    if ( p1 + numBytes > pack1->end || p2 + numBytes > pack2->end )
        return 0;

    if ( memcmp(p1, p2, numBytes) != 0 )
        return 0;

    pack1->cursor += numBytes;
    pack2->cursor += numBytes;
    return 1;
}

static int
_dnsPacket_isEqualQR( DnsPacket*  pack1, DnsPacket*  pack2 )
{
    /* compare domain name encoding + TYPE + CLASS */
    if ( !_dnsPacket_isEqualDomainName(pack1, pack2) ||
         !_dnsPacket_isEqualBytes(pack1, pack2, 2+2) )
        return 0;

    return 1;
}

static int
_dnsPacket_isEqualQuery( DnsPacket*  pack1, DnsPacket*  pack2 )
{
    int  count1, count2;

    /* compare the headers, ignore most fields */
    _dnsPacket_rewind(pack1);
    _dnsPacket_rewind(pack2);

    /* compare RD, ignore TC, see comment in _dnsPacket_checkQuery */
    if ((pack1->base[2] & 1) != (pack2->base[2] & 1)) {
        XLOG("different RD");
        return 0;
    }

    /* assume: other flags are all 0 */
    _dnsPacket_skip(pack1, 4);
    _dnsPacket_skip(pack2, 4);

    /* compare QDCOUNT */
    count1 = _dnsPacket_readInt16(pack1);
    count2 = _dnsPacket_readInt16(pack2);
    if (count1 != count2 || count1 < 0) {
        XLOG("different QDCOUNT");
        return 0;
    }

    /* assume: ANcount, NScount and ARcount are all 0 */
    _dnsPacket_skip(pack1, 6);
    _dnsPacket_skip(pack2, 6);

    /* compare the QDCOUNT QRs */
    for ( ; count1 > 0; count1-- ) {
        if (!_dnsPacket_isEqualQR(pack1, pack2)) {
            XLOG("different QR");
            return 0;
        }
    }
    return 1;
}

/****************************************************************************/
/****************************************************************************/
/*****                                                                  *****/
/*****                                                                  *****/
/*****                                                                  *****/
/****************************************************************************/
/****************************************************************************/

/* cache entry. for simplicity, 'hash' and 'hlink' are inlined in this
 * structure though they are conceptually part of the hash table.
 *
 * similarly, mru_next and mru_prev are part of the global MRU list
 */
typedef struct Entry {
    unsigned int     hash;   /* hash value */
    struct Entry*    hlink;  /* next in collision chain */
    struct Entry*    mru_prev;
    struct Entry*    mru_next;

    const uint8_t*   query;
    int              querylen;
    const uint8_t*   answer;
    int              answerlen;
    time_t           when;   /* time_t when entry was added to table */
    int              id;     /* for debugging purpose */
} Entry;


static void
entry_free( Entry*  e )
{
    /* everything is allocated in a single memory block */
    if (e) {
        free(e);
    }
}

static __inline__ void
entry_mru_remove( Entry*  e )
{
    e->mru_prev->mru_next = e->mru_next;
    e->mru_next->mru_prev = e->mru_prev;
}

static __inline__ void
entry_mru_add( Entry*  e, Entry*  list )
{
    Entry*  first = list->mru_next;

    e->mru_next = first;
    e->mru_prev = list;

    list->mru_next  = e;
    first->mru_prev = e;
}

/* compute the hash of a given entry, this is a hash of most
 * data in the query (key) */
static unsigned
entry_hash( const Entry*  e )
{
    DnsPacket  pack[1];

    _dnsPacket_init(pack, e->query, e->querylen);
    return _dnsPacket_hashQuery(pack);
}

/* initialize an Entry as a search key, this also checks the input query packet
 * returns 1 on success, or 0 in case of unsupported/malformed data */
static int
entry_init_key( Entry*  e, const void*  query, int  querylen )
{
    DnsPacket  pack[1];

    memset(e, 0, sizeof(*e));

    e->query    = query;
    e->querylen = querylen;
    e->hash     = entry_hash(e);

    _dnsPacket_init(pack, query, querylen);

    return _dnsPacket_checkQuery(pack);
}

/* allocate a new entry as a cache node */
static Entry*
entry_alloc( const Entry*  init, const void*  answer, int  answerlen )
{
    Entry*  e;
    int     size;

    size = sizeof(*e) + init->querylen + answerlen;
    e    = calloc(size, 1);
    if (e == NULL)
        return e;

    e->hash     = init->hash;
    e->query    = (const uint8_t*)(e+1);
    e->querylen = init->querylen;

    memcpy( (char*)e->query, init->query, e->querylen );

    e->answer    = e->query + e->querylen;
    e->answerlen = answerlen;

    memcpy( (char*)e->answer, answer, e->answerlen );

    e->when  = _time_now();

    return e;
}

static int
entry_equals( const Entry*  e1, const Entry*  e2 )
{
    DnsPacket  pack1[1], pack2[1];

    if (e1->querylen != e2->querylen) {
        return 0;
    }
    _dnsPacket_init(pack1, e1->query, e1->querylen);
    _dnsPacket_init(pack2, e2->query, e2->querylen);

    return _dnsPacket_isEqualQuery(pack1, pack2);
}

/****************************************************************************/
/****************************************************************************/
/*****                                                                  *****/
/*****                                                                  *****/
/*****                                                                  *****/
/****************************************************************************/
/****************************************************************************/

/* We use a simple hash table with external collision lists
 * for simplicity, the hash-table fields 'hash' and 'hlink' are
 * inlined in the Entry structure.
 */
#define  MAX_HASH_ENTRIES   (2*CONFIG_MAX_ENTRIES)

typedef struct resolv_cache {
    int              num_entries;
    Entry            mru_list;
    pthread_mutex_t  lock;
    unsigned         generation;
    int              last_id;
    Entry*           entries[ MAX_HASH_ENTRIES ];
} Cache;


#define  HTABLE_VALID(x)  ((x) != NULL && (x) != HTABLE_DELETED)

static void
_cache_flush_locked( Cache*  cache )
{
    int     nn;
    time_t  now = _time_now();

    for (nn = 0; nn < MAX_HASH_ENTRIES; nn++) 
    {
        Entry**  pnode = &cache->entries[nn];

        while (*pnode != NULL) {
            Entry*  node = *pnode;
            *pnode = node->hlink;
            entry_free(node);
        }
    }

    cache->mru_list.mru_next = cache->mru_list.mru_prev = &cache->mru_list;
    cache->num_entries       = 0;
    cache->last_id           = 0;

    XLOG("*************************\n"
         "*** DNS CACHE FLUSHED ***\n"
         "*************************");
}

struct resolv_cache*
_resolv_cache_create( void )
{
    struct resolv_cache*  cache;

    cache = calloc(sizeof(*cache), 1);
    if (cache) {
        cache->generation = ~0U;
        pthread_mutex_init( &cache->lock, NULL );
        cache->mru_list.mru_prev = cache->mru_list.mru_next = &cache->mru_list;
        XLOG("%s: cache created\n", __FUNCTION__);
    }
    return cache;
}


#if DEBUG
static void
_dump_query( const uint8_t*  query, int  querylen )
{
    char       temp[256], *p=temp, *end=p+sizeof(temp);
    DnsPacket  pack[1];

    _dnsPacket_init(pack, query, querylen);
    p = _dnsPacket_bprintQuery(pack, p, end);
    XLOG("QUERY: %s", temp);
}

static void
_cache_dump_mru( Cache*  cache )
{
    char    temp[512], *p=temp, *end=p+sizeof(temp);
    Entry*  e;

    p = _bprint(temp, end, "MRU LIST (%2d): ", cache->num_entries);
    for (e = cache->mru_list.mru_next; e != &cache->mru_list; e = e->mru_next)
        p = _bprint(p, end, " %d", e->id);

    XLOG("%s", temp);
}
#endif

#if DEBUG
#  define  XLOG_QUERY(q,len)   _dump_query((q), (len))
#else
#  define  XLOG_QUERY(q,len)   ((void)0)
#endif

/* This function tries to find a key within the hash table
 * In case of success, it will return a *pointer* to the hashed key.
 * In case of failure, it will return a *pointer* to NULL
 *
 * So, the caller must check '*result' to check for success/failure.
 *
 * The main idea is that the result can later be used directly in
 * calls to _resolv_cache_add or _resolv_cache_remove as the 'lookup'
 * parameter. This makes the code simpler and avoids re-searching
 * for the key position in the htable.
 *
 * The result of a lookup_p is only valid until you alter the hash
 * table.
 */
static Entry**
_cache_lookup_p( Cache*   cache,
                 Entry*   key )
{
    int      index = key->hash % MAX_HASH_ENTRIES;
    Entry**  pnode = &cache->entries[ key->hash % MAX_HASH_ENTRIES ];

    while (*pnode != NULL) {
        Entry*  node = *pnode;

        if (node == NULL)
            break;

        if (node->hash == key->hash && entry_equals(node, key))
            break;

        pnode = &node->hlink;
    }
    return pnode; 
}

/* Add a new entry to the hash table. 'lookup' must be the
 * result of an immediate previous failed _lookup_p() call
 * (i.e. with *lookup == NULL), and 'e' is the pointer to the
 * newly created entry
 */
static void
_cache_add_p( Cache*   cache,
              Entry**  lookup,
              Entry*   e )
{
    *lookup = e;
    e->id = ++cache->last_id;
    entry_mru_add(e, &cache->mru_list);
    cache->num_entries += 1;

    XLOG("%s: entry %d added (count=%d)", __FUNCTION__,
         e->id, cache->num_entries);
}

/* Remove an existing entry from the hash table,
 * 'lookup' must be the result of an immediate previous
 * and succesful _lookup_p() call.
 */
static void
_cache_remove_p( Cache*   cache,
                 Entry**  lookup )
{
    Entry*  e  = *lookup;

    XLOG("%s: entry %d removed (count=%d)", __FUNCTION__,
         e->id, cache->num_entries-1);

    entry_mru_remove(e);
    *lookup = e->hlink;
    entry_free(e);
    cache->num_entries -= 1;
}

/* Remove the oldest entry from the hash table.
 */
static void
_cache_remove_oldest( Cache*  cache )
{
    Entry*   oldest = cache->mru_list.mru_prev;
    Entry**  lookup = _cache_lookup_p(cache, oldest);

    if (*lookup == NULL) { /* should not happen */
        XLOG("%s: OLDEST NOT IN HTABLE ?", __FUNCTION__);
        return;
    }
    _cache_remove_p(cache, lookup);
}


ResolvCacheStatus
_resolv_cache_lookup( struct resolv_cache*  cache,
                      const void*           query,
                      int                   querylen,
                      void*                 answer,
                      int                   answersize,
                      int                  *answerlen )
{
    DnsPacket  pack[1];
    Entry      key[1];
    int        index;
    Entry**    lookup;
    Entry*     e;
    time_t     now;

    ResolvCacheStatus  result = RESOLV_CACHE_NOTFOUND;

    XLOG("%s: lookup", __FUNCTION__);
    XLOG_QUERY(query, querylen);

    /* we don't cache malformed queries */
    if (!entry_init_key(key, query, querylen)) {
        XLOG("%s: unsupported query", __FUNCTION__);
        return RESOLV_CACHE_UNSUPPORTED;
    }
    /* lookup cache */
    pthread_mutex_lock( &cache->lock );

    /* see the description of _lookup_p to understand this.
     * the function always return a non-NULL pointer.
     */
    lookup = _cache_lookup_p(cache, key);
    e      = *lookup;

    if (e == NULL) {
        XLOG( "NOT IN CACHE");
        goto Exit;
    }

    now = _time_now();

    /* remove stale entries here */
    if ( (unsigned)(now - e->when) >= CONFIG_SECONDS ) {
        XLOG( " NOT IN CACHE (STALE ENTRY %p DISCARDED)", *lookup );
        _cache_remove_p(cache, lookup);
        goto Exit;
    }

    *answerlen = e->answerlen;
    if (e->answerlen > answersize) {
        /* NOTE: we return UNSUPPORTED if the answer buffer is too short */
        result = RESOLV_CACHE_UNSUPPORTED;
        XLOG(" ANSWER TOO LONG");
        goto Exit;
    }

    memcpy( answer, e->answer, e->answerlen );

    /* bump up this entry to the top of the MRU list */
    if (e != cache->mru_list.mru_next) {
        entry_mru_remove( e );
        entry_mru_add( e, &cache->mru_list );
    }

    XLOG( "FOUND IN CACHE entry=%p", e );
    result = RESOLV_CACHE_FOUND;

Exit:
    pthread_mutex_unlock( &cache->lock );
    return result;
}


void
_resolv_cache_add( struct resolv_cache*  cache,
                   const void*           query,
                   int                   querylen,
                   const void*           answer,
                   int                   answerlen )
{
    Entry    key[1];
    Entry*   e;
    Entry**  lookup;

    /* don't assume that the query has already been cached
     */
    if (!entry_init_key( key, query, querylen )) {
        XLOG( "%s: passed invalid query ?", __FUNCTION__);
        return;
    }

    pthread_mutex_lock( &cache->lock );

    XLOG( "%s: query:", __FUNCTION__ );
    XLOG_QUERY(query,querylen);
#if DEBUG_DATA
    XLOG( "answer:");
    XLOG_BYTES(answer,answerlen);
#endif

    lookup = _cache_lookup_p(cache, key);
    e      = *lookup;

    if (e != NULL) { /* should not happen */
        XLOG("%s: ALREADY IN CACHE (%p) ? IGNORING ADD",
             __FUNCTION__, e);
        goto Exit;
    }

    if (cache->num_entries >= CONFIG_MAX_ENTRIES) {
        _cache_remove_oldest(cache);
        /* need to lookup again */
        lookup = _cache_lookup_p(cache, key);
        e      = *lookup;
        if (e != NULL) {
            XLOG("%s: ALREADY IN CACHE (%p) ? IGNORING ADD",
                __FUNCTION__, e);
            goto Exit;
        }
    }

    e = entry_alloc( key, answer, answerlen );
    if (e != NULL) {
        _cache_add_p(cache, lookup, e);
    }
#if DEBUG
    _cache_dump_mru(cache);
#endif
Exit:
    pthread_mutex_unlock( &cache->lock );
}

/****************************************************************************/
/****************************************************************************/
/*****                                                                  *****/
/*****                                                                  *****/
/*****                                                                  *****/
/****************************************************************************/
/****************************************************************************/

static struct resolv_cache*  _res_cache;
static pthread_once_t        _res_cache_once;

static void
_res_cache_init( void )
{
    const char*  env = getenv(CONFIG_ENV);

    if (env && atoi(env) == 0) {
        /* the cache is disabled */
        return;
    }

    _res_cache = _resolv_cache_create();
}


struct resolv_cache*
__get_res_cache( void )
{
    pthread_once( &_res_cache_once, _res_cache_init );
    return _res_cache;
}

void
_resolv_cache_reset( unsigned  generation )
{
    XLOG("%s: generation=%d", __FUNCTION__, generation);

    if (_res_cache == NULL)
        return;

    pthread_mutex_lock( &_res_cache->lock );
    if (_res_cache->generation != generation) {
        _cache_flush_locked(_res_cache);
        _res_cache->generation = generation;
    }
    pthread_mutex_unlock( &_res_cache->lock );
}
