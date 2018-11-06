#include <sqlite3_ruby.h>

void rb_sqlite3_raise(sqlite3 * db, int status)
{
  VALUE klass = Qnil;

  switch(status) {
    case SQLITE_OK:
      return;
      break;
    case SQLITE_ERROR:
      klass = rb_path2class("SQLite3::SQLException");
      break;
    case SQLITE_INTERNAL:
      klass = rb_path2class("SQLite3::InternalException");
      break;
    case SQLITE_PERM:
      klass = rb_path2class("SQLite3::PermissionException");
      break;
    case SQLITE_ABORT:
      klass = rb_path2class("SQLite3::AbortException");
      break;
    case SQLITE_BUSY:
      klass = rb_path2class("SQLite3::BusyException");
      break;
    case SQLITE_LOCKED:
      klass = rb_path2class("SQLite3::LockedException");
      break;
    case SQLITE_NOMEM:
      klass = rb_path2class("SQLite3::MemoryException");
      break;
    case SQLITE_READONLY:
      klass = rb_path2class("SQLite3::ReadOnlyException");
      break;
    case SQLITE_INTERRUPT:
      klass = rb_path2class("SQLite3::InterruptException");
      break;
    case SQLITE_IOERR:
      klass = rb_path2class("SQLite3::IOException");
      break;
    case SQLITE_CORRUPT:
      klass = rb_path2class("SQLite3::CorruptException");
      break;
    case SQLITE_NOTFOUND:
      klass = rb_path2class("SQLite3::NotFoundException");
      break;
    case SQLITE_FULL:
      klass = rb_path2class("SQLite3::FullException");
      break;
    case SQLITE_CANTOPEN:
      klass = rb_path2class("SQLite3::CantOpenException");
      break;
    case SQLITE_PROTOCOL:
      klass = rb_path2class("SQLite3::ProtocolException");
      break;
    case SQLITE_EMPTY:
      klass = rb_path2class("SQLite3::EmptyException");
      break;
    case SQLITE_SCHEMA:
      klass = rb_path2class("SQLite3::SchemaChangedException");
      break;
    case SQLITE_TOOBIG:
      klass = rb_path2class("SQLite3::TooBigException");
      break;
    case SQLITE_CONSTRAINT:
      klass = rb_path2class("SQLite3::ConstraintException");
      break;
    case SQLITE_MISMATCH:
      klass = rb_path2class("SQLite3::MismatchException");
      break;
    case SQLITE_MISUSE:
      klass = rb_path2class("SQLite3::MisuseException");
      break;
    case SQLITE_NOLFS:
      klass = rb_path2class("SQLite3::UnsupportedException");
      break;
    case SQLITE_AUTH:
      klass = rb_path2class("SQLite3::AuthorizationException");
      break;
    case SQLITE_FORMAT:
      klass = rb_path2class("SQLite3::FormatException");
      break;
    case SQLITE_RANGE:
      klass = rb_path2class("SQLite3::RangeException");
      break;
    case SQLITE_NOTADB:
      klass = rb_path2class("SQLite3::NotADatabaseException");
      break;
    default:
      klass = rb_eRuntimeError;
  }

  rb_raise(klass, "%s", sqlite3_errmsg(db));
}
