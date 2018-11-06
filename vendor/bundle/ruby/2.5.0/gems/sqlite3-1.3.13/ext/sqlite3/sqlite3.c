#include <sqlite3_ruby.h>

VALUE mSqlite3;
VALUE cSqlite3Blob;

int bignum_to_int64(VALUE value, sqlite3_int64 *result)
{
#ifdef HAVE_RB_INTEGER_PACK
  const int nails = 0;
  int t = rb_integer_pack(value, result, 1, sizeof(*result), nails,
			  INTEGER_PACK_NATIVE_BYTE_ORDER|
			  INTEGER_PACK_2COMP);
  switch (t) {
  case -2: case +2:
    return 0;
  case +1:
    if (!nails) {
      if (*result < 0) return 0;
    }
    break;
  case -1:
    if (!nails) {
      if (*result >= 0) return 0;
    }
    else {
      *result += INT64_MIN;
    }
    break;
  }
  return 1;
#else
# ifndef RBIGNUM_LEN
#   define RBIGNUM_LEN(x) RBIGNUM(x)->len
# endif
  const long len = RBIGNUM_LEN(value);
  if (len == 0) {
    *result = 0;
    return 1;
  }
  if (len > 63 / (SIZEOF_BDIGITS * CHAR_BIT) + 1) return 0;
  if (len == 63 / (SIZEOF_BDIGITS * CHAR_BIT) + 1) {
    const BDIGIT *digits = RBIGNUM_DIGITS(value);
    BDIGIT blast = digits[len-1];
    BDIGIT bmax = (BDIGIT)1UL << (63 % (CHAR_BIT * SIZEOF_BDIGITS));
    if (blast > bmax) return 0;
    if (blast == bmax) {
      if (RBIGNUM_POSITIVE_P(value)) {
	return 0;
      }
      else {
	long i = len-1;
	while (i) {
	  if (digits[--i]) return 0;
	}
      }
    }
  }
  *result = (sqlite3_int64)NUM2LL(value);
  return 1;
#endif
}

static VALUE libversion(VALUE UNUSED(klass))
{
  return INT2NUM(sqlite3_libversion_number());
}

/* Returns the compile time setting of the SQLITE_THREADSAFE flag.
 * See: https://www.sqlite.org/c3ref/threadsafe.html
 */
static VALUE threadsafe_p(VALUE UNUSED(klass))
{
  return INT2NUM(sqlite3_threadsafe());
}

void init_sqlite3_constants()
{
  VALUE mSqlite3Constants;
  VALUE mSqlite3Open;

  mSqlite3Constants = rb_define_module_under(mSqlite3, "Constants");

  /* sqlite3_open_v2 flags for Database::new */
  mSqlite3Open = rb_define_module_under(mSqlite3Constants, "Open");

  /* symbols = IO.readlines('sqlite3.h').map { |n| /\A#define\s+(SQLITE_OPEN_\w+)\s/ =~ n && $1 }.compact
   * pad = symbols.map(&:length).max - 9
   * symbols.each { |s| printf %Q{  rb_define_const(mSqlite3Open, %-#{pad}s INT2FIX(#{s}));\n}, '"' + s[12..-1] + '",' }
   */
  rb_define_const(mSqlite3Open, "READONLY",       INT2FIX(SQLITE_OPEN_READONLY));
  rb_define_const(mSqlite3Open, "READWRITE",      INT2FIX(SQLITE_OPEN_READWRITE));
  rb_define_const(mSqlite3Open, "CREATE",         INT2FIX(SQLITE_OPEN_CREATE));
  rb_define_const(mSqlite3Open, "DELETEONCLOSE",  INT2FIX(SQLITE_OPEN_DELETEONCLOSE));
  rb_define_const(mSqlite3Open, "EXCLUSIVE",      INT2FIX(SQLITE_OPEN_EXCLUSIVE));
  rb_define_const(mSqlite3Open, "MAIN_DB",        INT2FIX(SQLITE_OPEN_MAIN_DB));
  rb_define_const(mSqlite3Open, "TEMP_DB",        INT2FIX(SQLITE_OPEN_TEMP_DB));
  rb_define_const(mSqlite3Open, "TRANSIENT_DB",   INT2FIX(SQLITE_OPEN_TRANSIENT_DB));
  rb_define_const(mSqlite3Open, "MAIN_JOURNAL",   INT2FIX(SQLITE_OPEN_MAIN_JOURNAL));
  rb_define_const(mSqlite3Open, "TEMP_JOURNAL",   INT2FIX(SQLITE_OPEN_TEMP_JOURNAL));
  rb_define_const(mSqlite3Open, "SUBJOURNAL",     INT2FIX(SQLITE_OPEN_SUBJOURNAL));
  rb_define_const(mSqlite3Open, "MASTER_JOURNAL", INT2FIX(SQLITE_OPEN_MASTER_JOURNAL));
  rb_define_const(mSqlite3Open, "NOMUTEX",        INT2FIX(SQLITE_OPEN_NOMUTEX));
  rb_define_const(mSqlite3Open, "FULLMUTEX",      INT2FIX(SQLITE_OPEN_FULLMUTEX));
#ifdef SQLITE_OPEN_AUTOPROXY
  /* SQLITE_VERSION_NUMBER>=3007002 */
  rb_define_const(mSqlite3Open, "AUTOPROXY",      INT2FIX(SQLITE_OPEN_AUTOPROXY));
  rb_define_const(mSqlite3Open, "SHAREDCACHE",    INT2FIX(SQLITE_OPEN_SHAREDCACHE));
  rb_define_const(mSqlite3Open, "PRIVATECACHE",   INT2FIX(SQLITE_OPEN_PRIVATECACHE));
  rb_define_const(mSqlite3Open, "WAL",            INT2FIX(SQLITE_OPEN_WAL));
#endif
#ifdef SQLITE_OPEN_URI
  /* SQLITE_VERSION_NUMBER>=3007007 */
  rb_define_const(mSqlite3Open, "URI",            INT2FIX(SQLITE_OPEN_URI));
#endif
#ifdef SQLITE_OPEN_MEMORY
  /* SQLITE_VERSION_NUMBER>=3007013 */
  rb_define_const(mSqlite3Open, "MEMORY",         INT2FIX(SQLITE_OPEN_MEMORY));
#endif
}

void Init_sqlite3_native()
{
  /*
   * SQLite3 is a wrapper around the popular database
   * sqlite[http://sqlite.org].
   *
   * For an example of usage, see SQLite3::Database.
   */
  mSqlite3     = rb_define_module("SQLite3");

  /* A class for differentiating between strings and blobs, when binding them
   * into statements.
   */
  cSqlite3Blob = rb_define_class_under(mSqlite3, "Blob", rb_cString);

  /* Initialize the sqlite3 library */
#ifdef HAVE_SQLITE3_INITIALIZE
  sqlite3_initialize();
#endif

  init_sqlite3_constants();
  init_sqlite3_database();
  init_sqlite3_statement();
#ifdef HAVE_SQLITE3_BACKUP_INIT
  init_sqlite3_backup();
#endif

  rb_define_singleton_method(mSqlite3, "libversion", libversion, 0);
  rb_define_singleton_method(mSqlite3, "threadsafe", threadsafe_p, 0);
  rb_define_const(mSqlite3, "SQLITE_VERSION", rb_str_new2(SQLITE_VERSION));
  rb_define_const(mSqlite3, "SQLITE_VERSION_NUMBER", INT2FIX(SQLITE_VERSION_NUMBER));
}
