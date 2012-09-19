#ifndef __pg_h
#define __pg_h

#ifdef RUBY_EXTCONF_H
#	include RUBY_EXTCONF_H
#endif

/* System headers */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#if defined(HAVE_UNISTD_H) && !defined(_WIN32)
#	include <unistd.h>
#endif /* HAVE_UNISTD_H */

/* Ruby headers */
#include "ruby.h"
#ifdef HAVE_RUBY_ST_H
#	include "ruby/st.h"
#elif HAVE_ST_H
#	include "st.h"
#endif

#if defined(HAVE_RUBY_ENCODING_H) && HAVE_RUBY_ENCODING_H
#	include "ruby/encoding.h"
#	define M17N_SUPPORTED
#	define ASSOCIATE_INDEX( obj, index_holder ) rb_enc_associate_index((obj), pg_enc_get_index((index_holder)))
#	ifdef HAVE_RB_ENCDB_ALIAS
		extern int rb_encdb_alias(const char *, const char *);
#		define ENC_ALIAS(name, orig) rb_encdb_alias((name), (orig))
#	elif HAVE_RB_ENC_ALIAS
		extern int rb_enc_alias(const char *, const char *);
#		define ENC_ALIAS(name, orig) rb_enc_alias((name), (orig))
#	else
		extern int rb_enc_alias(const char *alias, const char *orig); /* declaration missing in Ruby 1.9.1 */
#		define ENC_ALIAS(name, orig) rb_enc_alias((name), (orig))
#	endif
#else
#	define ASSOCIATE_INDEX( obj, index_holder ) /* nothing */
#endif

#if RUBY_VM != 1
#	define RUBY_18_COMPAT
#endif

#ifndef RARRAY_LEN
#	define RARRAY_LEN(x) RARRAY((x))->len
#endif /* RARRAY_LEN */

#ifndef RSTRING_LEN
#	define RSTRING_LEN(x) RSTRING((x))->len
#endif /* RSTRING_LEN */

#ifndef RSTRING_PTR
#	define RSTRING_PTR(x) RSTRING((x))->ptr
#endif /* RSTRING_PTR */

#ifndef StringValuePtr
#	define StringValuePtr(x) STR2CSTR(x)
#endif /* StringValuePtr */

#ifdef RUBY_18_COMPAT
#	define rb_io_stdio_file GetWriteFile
#	include "rubyio.h"
#else
#	include "ruby/io.h"
#endif

/* PostgreSQL headers */
#include "libpq-fe.h"
#include "libpq/libpq-fs.h"              /* large-object interface */
#include "pg_config_manual.h"

#if defined(_WIN32)
#	include <fcntl.h>
__declspec(dllexport)
typedef long suseconds_t;
#endif


/***************************************************************************
 * Globals
 **************************************************************************/

extern VALUE rb_mPG;
extern VALUE rb_ePGerror;
extern VALUE rb_mPGconstants;
extern VALUE rb_cPGconn;
extern VALUE rb_cPGresult;


/***************************************************************************
 * MACROS
 **************************************************************************/

#define UNUSED(x) ((void)(x))
#define SINGLETON_ALIAS(klass,new,old) rb_define_alias(rb_singleton_class((klass)),(new),(old))


/***************************************************************************
 * PROTOTYPES
 **************************************************************************/
void Init_pg_ext                                       _(( void ));

void init_pg_connection                                _(( void ));
void init_pg_result                                    _(( void ));

PGconn *pg_get_pgconn	                               _(( VALUE ));

VALUE pg_new_result                                    _(( PGresult *, PGconn * ));
void pg_check_result                                   _(( VALUE, VALUE ));
VALUE pg_result_clear                                  _(( VALUE ));

#ifdef M17N_SUPPORTED
rb_encoding * pg_get_pg_encoding_as_rb_encoding        _(( int ));
rb_encoding * pg_get_pg_encname_as_rb_encoding         _(( const char * ));
const char * pg_get_rb_encoding_as_pg_encoding         _(( rb_encoding * ));
int pg_enc_get_index                                   _(( VALUE ));
rb_encoding *pg_conn_enc_get                           _(( PGconn * ));
#endif /* M17N_SUPPORTED */


#endif /* end __pg_h */
