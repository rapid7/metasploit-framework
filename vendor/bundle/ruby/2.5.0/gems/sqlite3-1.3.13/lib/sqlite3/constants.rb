module SQLite3 ; module Constants

  module TextRep
    UTF8    = 1
    UTF16LE = 2
    UTF16BE = 3
    UTF16   = 4
    ANY     = 5
  end

  module ColumnType
    INTEGER = 1
    FLOAT   = 2
    TEXT    = 3
    BLOB    = 4
    NULL    = 5
  end

  module ErrorCode
    OK         =  0   # Successful result
    ERROR      =  1   # SQL error or missing database
    INTERNAL   =  2   # An internal logic error in SQLite
    PERM       =  3   # Access permission denied
    ABORT      =  4   # Callback routine requested an abort
    BUSY       =  5   # The database file is locked
    LOCKED     =  6   # A table in the database is locked
    NOMEM      =  7   # A malloc() failed
    READONLY   =  8   # Attempt to write a readonly database
    INTERRUPT  =  9   # Operation terminated by sqlite_interrupt()
    IOERR      = 10   # Some kind of disk I/O error occurred
    CORRUPT    = 11   # The database disk image is malformed
    NOTFOUND   = 12   # (Internal Only) Table or record not found
    FULL       = 13   # Insertion failed because database is full
    CANTOPEN   = 14   # Unable to open the database file
    PROTOCOL   = 15   # Database lock protocol error
    EMPTY      = 16   # (Internal Only) Database table is empty
    SCHEMA     = 17   # The database schema changed
    TOOBIG     = 18   # Too much data for one row of a table
    CONSTRAINT = 19   # Abort due to contraint violation
    MISMATCH   = 20   # Data type mismatch
    MISUSE     = 21   # Library used incorrectly
    NOLFS      = 22   # Uses OS features not supported on host
    AUTH       = 23   # Authorization denied

    ROW        = 100  # sqlite_step() has another row ready
    DONE       = 101  # sqlite_step() has finished executing
  end

end ; end
