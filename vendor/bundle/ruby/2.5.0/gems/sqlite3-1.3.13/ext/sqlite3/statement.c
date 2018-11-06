#include <sqlite3_ruby.h>

#define REQUIRE_OPEN_STMT(_ctxt) \
  if(!_ctxt->st) \
    rb_raise(rb_path2class("SQLite3::Exception"), "cannot use a closed statement");

VALUE cSqlite3Statement;

static void deallocate(void * ctx)
{
  sqlite3StmtRubyPtr c = (sqlite3StmtRubyPtr)ctx;
  xfree(c);
}

static VALUE allocate(VALUE klass)
{
  sqlite3StmtRubyPtr ctx = xcalloc((size_t)1, sizeof(sqlite3StmtRuby));
  ctx->st     = NULL;
  ctx->done_p = 0;

  return Data_Wrap_Struct(klass, NULL, deallocate, ctx);
}

/* call-seq: SQLite3::Statement.new(db, sql)
 *
 * Create a new statement attached to the given Database instance, and which
 * encapsulates the given SQL text. If the text contains more than one
 * statement (i.e., separated by semicolons), then the #remainder property
 * will be set to the trailing text.
 */
static VALUE initialize(VALUE self, VALUE db, VALUE sql)
{
  sqlite3RubyPtr db_ctx;
  sqlite3StmtRubyPtr ctx;
  const char *tail = NULL;
  int status;

  StringValue(sql);

  Data_Get_Struct(db, sqlite3Ruby, db_ctx);
  Data_Get_Struct(self, sqlite3StmtRuby, ctx);

  if(!db_ctx->db)
    rb_raise(rb_eArgError, "prepare called on a closed database");

#ifdef HAVE_RUBY_ENCODING_H
  if(!UTF8_P(sql)) {
    sql               = rb_str_export_to_enc(sql, rb_utf8_encoding());
  }
#endif

#ifdef HAVE_SQLITE3_PREPARE_V2
  status = sqlite3_prepare_v2(
#else
  status = sqlite3_prepare(
#endif
      db_ctx->db,
      (const char *)StringValuePtr(sql),
      (int)RSTRING_LEN(sql),
      &ctx->st,
      &tail
  );

  CHECK(db_ctx->db, status);

  rb_iv_set(self, "@connection", db);
  rb_iv_set(self, "@remainder", rb_str_new2(tail));
  rb_iv_set(self, "@columns", Qnil);
  rb_iv_set(self, "@types", Qnil);

  return self;
}

/* call-seq: stmt.close
 *
 * Closes the statement by finalizing the underlying statement
 * handle. The statement must not be used after being closed.
 */
static VALUE sqlite3_rb_close(VALUE self)
{
  sqlite3StmtRubyPtr ctx;

  Data_Get_Struct(self, sqlite3StmtRuby, ctx);

  REQUIRE_OPEN_STMT(ctx);

  sqlite3_finalize(ctx->st);
  ctx->st = NULL;

  return self;
}

/* call-seq: stmt.closed?
 *
 * Returns true if the statement has been closed.
 */
static VALUE closed_p(VALUE self)
{
  sqlite3StmtRubyPtr ctx;
  Data_Get_Struct(self, sqlite3StmtRuby, ctx);

  if(!ctx->st) return Qtrue;

  return Qfalse;
}

static VALUE step(VALUE self)
{
  sqlite3StmtRubyPtr ctx;
  sqlite3_stmt *stmt;
  int value, length;
  VALUE list;
#ifdef HAVE_RUBY_ENCODING_H
  rb_encoding * internal_encoding;
#endif

  Data_Get_Struct(self, sqlite3StmtRuby, ctx);

  REQUIRE_OPEN_STMT(ctx);

  if(ctx->done_p) return Qnil;

#ifdef HAVE_RUBY_ENCODING_H
  {
      VALUE db          = rb_iv_get(self, "@connection");
      rb_funcall(db, rb_intern("encoding"), 0);
      internal_encoding = rb_default_internal_encoding();
  }
#endif

  stmt = ctx->st;

  value = sqlite3_step(stmt);
  length = sqlite3_column_count(stmt);
  list = rb_ary_new2((long)length);

  switch(value) {
    case SQLITE_ROW:
      {
        int i;
        for(i = 0; i < length; i++) {
          switch(sqlite3_column_type(stmt, i)) {
            case SQLITE_INTEGER:
              rb_ary_push(list, LL2NUM(sqlite3_column_int64(stmt, i)));
              break;
            case SQLITE_FLOAT:
              rb_ary_push(list, rb_float_new(sqlite3_column_double(stmt, i)));
              break;
            case SQLITE_TEXT:
              {
                VALUE str = rb_tainted_str_new(
                    (const char *)sqlite3_column_text(stmt, i),
                    (long)sqlite3_column_bytes(stmt, i)
                );
#ifdef HAVE_RUBY_ENCODING_H
                rb_enc_associate_index(str, rb_utf8_encindex());
                if(internal_encoding)
                  str = rb_str_export_to_enc(str, internal_encoding);
#endif
                rb_ary_push(list, str);
              }
              break;
            case SQLITE_BLOB:
              {
                VALUE str = rb_tainted_str_new(
                    (const char *)sqlite3_column_blob(stmt, i),
                    (long)sqlite3_column_bytes(stmt, i)
                );
                rb_ary_push(list, str);
              }
              break;
            case SQLITE_NULL:
              rb_ary_push(list, Qnil);
              break;
            default:
              rb_raise(rb_eRuntimeError, "bad type");
          }
        }
      }
      break;
    case SQLITE_DONE:
      ctx->done_p = 1;
      return Qnil;
      break;
    default:
      sqlite3_reset(stmt);
      ctx->done_p = 0;
      CHECK(sqlite3_db_handle(ctx->st), value);
  }

  return list;
}

/* call-seq: stmt.bind_param(key, value)
 *
 * Binds value to the named (or positional) placeholder. If +param+ is a
 * Fixnum, it is treated as an index for a positional placeholder.
 * Otherwise it is used as the name of the placeholder to bind to.
 *
 * See also #bind_params.
 */
static VALUE bind_param(VALUE self, VALUE key, VALUE value)
{
  sqlite3StmtRubyPtr ctx;
  int status;
  int index;

  Data_Get_Struct(self, sqlite3StmtRuby, ctx);
  REQUIRE_OPEN_STMT(ctx);

  switch(TYPE(key)) {
    case T_SYMBOL:
      key = rb_funcall(key, rb_intern("to_s"), 0);
    case T_STRING:
      if(RSTRING_PTR(key)[0] != ':') key = rb_str_plus(rb_str_new2(":"), key);
      index = sqlite3_bind_parameter_index(ctx->st, StringValuePtr(key));
      break;
    default:
      index = (int)NUM2INT(key);
  }

  if(index == 0)
    rb_raise(rb_path2class("SQLite3::Exception"), "no such bind parameter");

  switch(TYPE(value)) {
    case T_STRING:
      if(CLASS_OF(value) == cSqlite3Blob
#ifdef HAVE_RUBY_ENCODING_H
              || rb_enc_get_index(value) == rb_ascii8bit_encindex()
#endif
        ) {
        status = sqlite3_bind_blob(
            ctx->st,
            index,
            (const char *)StringValuePtr(value),
            (int)RSTRING_LEN(value),
            SQLITE_TRANSIENT
            );
      } else {


#ifdef HAVE_RUBY_ENCODING_H
        if (UTF16_LE_P(value) || UTF16_BE_P(value)) {
          status = sqlite3_bind_text16(
              ctx->st,
              index,
              (const char *)StringValuePtr(value),
              (int)RSTRING_LEN(value),
              SQLITE_TRANSIENT
              );
        } else {
          if (!UTF8_P(value) || !USASCII_P(value)) {
              value = rb_str_encode(value, rb_enc_from_encoding(rb_utf8_encoding()), 0, Qnil);
          }
#endif
        status = sqlite3_bind_text(
            ctx->st,
            index,
            (const char *)StringValuePtr(value),
            (int)RSTRING_LEN(value),
            SQLITE_TRANSIENT
            );
#ifdef HAVE_RUBY_ENCODING_H
        }
#endif
      }
      break;
    case T_BIGNUM: {
      sqlite3_int64 num64;
      if (bignum_to_int64(value, &num64)) {
          status = sqlite3_bind_int64(ctx->st, index, num64);
          break;
      }
    }
    case T_FLOAT:
      status = sqlite3_bind_double(ctx->st, index, NUM2DBL(value));
      break;
    case T_FIXNUM:
      status = sqlite3_bind_int64(ctx->st, index, (sqlite3_int64)FIX2LONG(value));
      break;
    case T_NIL:
      status = sqlite3_bind_null(ctx->st, index);
      break;
    default:
      rb_raise(rb_eRuntimeError, "can't prepare %s",
          rb_class2name(CLASS_OF(value)));
      break;
  }

  CHECK(sqlite3_db_handle(ctx->st), status);

  return self;
}

/* call-seq: stmt.reset!
 *
 * Resets the statement. This is typically done internally, though it might
 * occassionally be necessary to manually reset the statement.
 */
static VALUE reset_bang(VALUE self)
{
  sqlite3StmtRubyPtr ctx;

  Data_Get_Struct(self, sqlite3StmtRuby, ctx);
  REQUIRE_OPEN_STMT(ctx);

  sqlite3_reset(ctx->st);

  ctx->done_p = 0;

  return self;
}

/* call-seq: stmt.clear_bindings!
 *
 * Resets the statement. This is typically done internally, though it might
 * occassionally be necessary to manually reset the statement.
 */
static VALUE clear_bindings(VALUE self)
{
  sqlite3StmtRubyPtr ctx;

  Data_Get_Struct(self, sqlite3StmtRuby, ctx);
  REQUIRE_OPEN_STMT(ctx);

  sqlite3_clear_bindings(ctx->st);

  ctx->done_p = 0;

  return self;
}

/* call-seq: stmt.done?
 *
 * returns true if all rows have been returned.
 */
static VALUE done_p(VALUE self)
{
  sqlite3StmtRubyPtr ctx;
  Data_Get_Struct(self, sqlite3StmtRuby, ctx);

  if(ctx->done_p) return Qtrue;
  return Qfalse;
}

/* call-seq: stmt.column_count
 *
 * Returns the number of columns to be returned for this statement
 */
static VALUE column_count(VALUE self)
{
  sqlite3StmtRubyPtr ctx;
  Data_Get_Struct(self, sqlite3StmtRuby, ctx);
  REQUIRE_OPEN_STMT(ctx);

  return INT2NUM((long)sqlite3_column_count(ctx->st));
}

/* call-seq: stmt.column_name(index)
 *
 * Get the column name at +index+.  0 based.
 */
static VALUE column_name(VALUE self, VALUE index)
{
  sqlite3StmtRubyPtr ctx;
  const char * name;

  Data_Get_Struct(self, sqlite3StmtRuby, ctx);
  REQUIRE_OPEN_STMT(ctx);

  name = sqlite3_column_name(ctx->st, (int)NUM2INT(index));

  if(name) return SQLITE3_UTF8_STR_NEW2(name);
  return Qnil;
}

/* call-seq: stmt.column_decltype(index)
 *
 * Get the column type at +index+.  0 based.
 */
static VALUE column_decltype(VALUE self, VALUE index)
{
  sqlite3StmtRubyPtr ctx;
  const char * name;

  Data_Get_Struct(self, sqlite3StmtRuby, ctx);
  REQUIRE_OPEN_STMT(ctx);

  name = sqlite3_column_decltype(ctx->st, (int)NUM2INT(index));

  if(name) return rb_str_new2(name);
  return Qnil;
}

/* call-seq: stmt.bind_parameter_count
 *
 * Return the number of bind parameters
 */
static VALUE bind_parameter_count(VALUE self)
{
  sqlite3StmtRubyPtr ctx;
  Data_Get_Struct(self, sqlite3StmtRuby, ctx);
  REQUIRE_OPEN_STMT(ctx);

  return INT2NUM((long)sqlite3_bind_parameter_count(ctx->st));
}

#ifdef HAVE_SQLITE3_COLUMN_DATABASE_NAME

/* call-seq: stmt.database_name(column_index)
 *
 * Return the database name for the column at +column_index+
 */
static VALUE database_name(VALUE self, VALUE index)
{
  sqlite3StmtRubyPtr ctx;
  Data_Get_Struct(self, sqlite3StmtRuby, ctx);
  REQUIRE_OPEN_STMT(ctx);

  return SQLITE3_UTF8_STR_NEW2(
      sqlite3_column_database_name(ctx->st, NUM2INT(index)));
}

#endif

void init_sqlite3_statement()
{
  cSqlite3Statement = rb_define_class_under(mSqlite3, "Statement", rb_cObject);

  rb_define_alloc_func(cSqlite3Statement, allocate);
  rb_define_method(cSqlite3Statement, "initialize", initialize, 2);
  rb_define_method(cSqlite3Statement, "close", sqlite3_rb_close, 0);
  rb_define_method(cSqlite3Statement, "closed?", closed_p, 0);
  rb_define_method(cSqlite3Statement, "bind_param", bind_param, 2);
  rb_define_method(cSqlite3Statement, "reset!", reset_bang, 0);
  rb_define_method(cSqlite3Statement, "clear_bindings!", clear_bindings, 0);
  rb_define_method(cSqlite3Statement, "step", step, 0);
  rb_define_method(cSqlite3Statement, "done?", done_p, 0);
  rb_define_method(cSqlite3Statement, "column_count", column_count, 0);
  rb_define_method(cSqlite3Statement, "column_name", column_name, 1);
  rb_define_method(cSqlite3Statement, "column_decltype", column_decltype, 1);
  rb_define_method(cSqlite3Statement, "bind_parameter_count", bind_parameter_count, 0);

#ifdef HAVE_SQLITE3_COLUMN_DATABASE_NAME
  rb_define_method(cSqlite3Statement, "database_name", database_name, 1);
#endif
}
