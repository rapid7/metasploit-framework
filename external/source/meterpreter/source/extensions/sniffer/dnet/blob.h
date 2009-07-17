/*
 * blob.h
 *
 * Binary blob handling.
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: blob.h,v 1.2 2002/04/05 03:06:44 dugsong Exp $
 */

#ifndef DNET_BLOB_H
#define DNET_BLOB_H

typedef struct blob {
	u_char		*base;		/* start of data */
	int		 off;		/* offset into data */
	int		 end;		/* end of data */
	int		 size;		/* size of allocation */
} blob_t;

__BEGIN_DECLS
blob_t	*blob_new(void);

int	 blob_read(blob_t *b, void *buf, int len);
int	 blob_write(blob_t *b, const void *buf, int len);

int	 blob_seek(blob_t *b, int off, int whence);
#define  blob_skip(b, l)	blob_seek(b, l, SEEK_CUR)
#define  blob_rewind(b)		blob_seek(b, 0, SEEK_SET)

#define	 blob_offset(b)		((b)->off)
#define	 blob_left(b)		((b)->end - (b)->off)

int	 blob_index(blob_t *b, const void *buf, int len);
int	 blob_rindex(blob_t *b, const void *buf, int len);

int	 blob_pack(blob_t *b, const char *fmt, ...);
int	 blob_unpack(blob_t *b, const char *fmt, ...);

int	 blob_insert(blob_t *b, const void *buf, int len);
int	 blob_delete(blob_t *b, void *buf, int len);

int	 blob_print(blob_t *b, char *style, int len);

blob_t	*blob_free(blob_t *b);

int	 blob_register_alloc(size_t size, void *(*bmalloc)(size_t),
	    void (*bfree)(void *), void *(*brealloc)(void *, size_t));
#ifdef va_start
typedef int (*blob_fmt_cb)(int pack, int len, blob_t *b, va_list *arg);

int	 blob_register_pack(char c, blob_fmt_cb fmt_cb);
#endif
__END_DECLS

#endif /* DNET_BLOB_H */
