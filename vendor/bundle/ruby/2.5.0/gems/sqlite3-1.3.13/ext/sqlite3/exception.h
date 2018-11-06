#ifndef SQLITE3_EXCEPTION_RUBY
#define SQLITE3_EXCEPTION_RUBY

#define CHECK(_db, _status) rb_sqlite3_raise(_db, _status);

void rb_sqlite3_raise(sqlite3 * db, int status);

#endif
