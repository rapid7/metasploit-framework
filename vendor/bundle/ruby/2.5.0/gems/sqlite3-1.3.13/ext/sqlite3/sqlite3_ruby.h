#ifndef SQLITE3_RUBY
#define SQLITE3_RUBY

#include <ruby.h>

#ifdef UNUSED
#elif defined(__GNUC__)
# define UNUSED(x) UNUSED_ ## x __attribute__((unused))
#elif defined(__LCLINT__)
# define UNUSED(x) /*@unused@*/ x
#else
# define UNUSED(x) x
#endif

#ifdef HAVE_RUBY_ENCODING_H
#include <ruby/encoding.h>

#define USASCII_P(_obj) (rb_enc_get_index(_obj) == rb_usascii_encindex())
#define UTF8_P(_obj) (rb_enc_get_index(_obj) == rb_utf8_encindex())
#define UTF16_LE_P(_obj) (rb_enc_get_index(_obj) == rb_enc_find_index("UTF-16LE"))
#define UTF16_BE_P(_obj) (rb_enc_get_index(_obj) == rb_enc_find_index("UTF-16BE"))
#define SQLITE3_UTF8_STR_NEW2(_obj) \
    (rb_enc_associate_index(rb_str_new2(_obj), rb_utf8_encindex()))

#else

#define SQLITE3_UTF8_STR_NEW2(_obj) (rb_str_new2(_obj))

#endif


#include <sqlite3.h>

#ifndef HAVE_TYPE_SQLITE3_INT64
typedef sqlite_int64 sqlite3_int64;
#endif

#ifndef HAVE_TYPE_SQLITE3_UINT64
typedef sqlite_uint64 sqlite3_uint64;
#endif

extern VALUE mSqlite3;
extern VALUE cSqlite3Blob;

#include <database.h>
#include <statement.h>
#include <exception.h>
#include <backup.h>

int bignum_to_int64(VALUE big, sqlite3_int64 *result);

#endif
