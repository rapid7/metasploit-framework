#if !defined(SQLITE3_BACKUP_RUBY) && defined(HAVE_SQLITE3_BACKUP_INIT)
#define SQLITE3_BACKUP_RUBY

#include <sqlite3_ruby.h>

struct _sqlite3BackupRuby {
  sqlite3_backup *p;
};

typedef struct _sqlite3BackupRuby sqlite3BackupRuby;
typedef sqlite3BackupRuby * sqlite3BackupRubyPtr;

void init_sqlite3_backup();

#endif
