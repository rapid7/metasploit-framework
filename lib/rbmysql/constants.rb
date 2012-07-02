# -*- coding: binary -*-
# Copyright (C) 2003-2008 TOMITA Masahiro
# mailto:tommy@tmtm.org

class RbMysql
  # Command
  COM_SLEEP               = 0
  COM_QUIT                = 1
  COM_INIT_DB             = 2
  COM_QUERY               = 3
  COM_FIELD_LIST          = 4
  COM_CREATE_DB           = 5
  COM_DROP_DB             = 6
  COM_REFRESH             = 7
  COM_SHUTDOWN            = 8
  COM_STATISTICS          = 9
  COM_PROCESS_INFO        = 10
  COM_CONNECT             = 11
  COM_PROCESS_KILL        = 12
  COM_DEBUG               = 13
  COM_PING                = 14
  COM_TIME                = 15
  COM_DELAYED_INSERT      = 16
  COM_CHANGE_USER         = 17
  COM_BINLOG_DUMP         = 18
  COM_TABLE_DUMP          = 19
  COM_CONNECT_OUT         = 20
  COM_REGISTER_SLAVE      = 21
  COM_STMT_PREPARE        = 22
  COM_STMT_EXECUTE        = 23
  COM_STMT_SEND_LONG_DATA = 24
  COM_STMT_CLOSE          = 25
  COM_STMT_RESET          = 26
  COM_SET_OPTION          = 27
  COM_STMT_FETCH          = 28

  # Client flag
  CLIENT_LONG_PASSWORD     = 1         # new more secure passwords
  CLIENT_FOUND_ROWS        = 1 << 1    # Found instead of affected rows
  CLIENT_LONG_FLAG         = 1 << 2    # Get all column flags
  CLIENT_CONNECT_WITH_DB   = 1 << 3    # One can specify db on connect
  CLIENT_NO_SCHEMA         = 1 << 4    # Don't allow database.table.column
  CLIENT_COMPRESS          = 1 << 5    # Can use compression protocol
  CLIENT_ODBC              = 1 << 6    # Odbc client
  CLIENT_LOCAL_FILES       = 1 << 7    # Can use LOAD DATA LOCAL
  CLIENT_IGNORE_SPACE      = 1 << 8    # Ignore spaces before '('
  CLIENT_PROTOCOL_41       = 1 << 9    # New 4.1 protocol
  CLIENT_INTERACTIVE       = 1 << 10   # This is an interactive client
  CLIENT_SSL               = 1 << 11   # Switch to SSL after handshake
  CLIENT_IGNORE_SIGPIPE    = 1 << 12   # IGNORE sigpipes
  CLIENT_TRANSACTIONS      = 1 << 13   # Client knows about transactions
  CLIENT_RESERVED          = 1 << 14   # Old flag for 4.1 protocol
  CLIENT_SECURE_CONNECTION = 1 << 15   # New 4.1 authentication
  CLIENT_MULTI_STATEMENTS  = 1 << 16   # Enable/disable multi-stmt support
  CLIENT_MULTI_RESULTS     = 1 << 17   # Enable/disable multi-results

  # Connection Option
  OPT_CONNECT_TIMEOUT         = 0
  OPT_COMPRESS                = 1
  OPT_NAMED_PIPE              = 2
  INIT_COMMAND                = 3
  READ_DEFAULT_FILE           = 4
  READ_DEFAULT_GROUP          = 5
  SET_CHARSET_DIR             = 6
  SET_CHARSET_NAME            = 7
  OPT_LOCAL_INFILE            = 8
  OPT_PROTOCOL                = 9
  SHARED_MEMORY_BASE_NAME     = 10
  OPT_READ_TIMEOUT            = 11
  OPT_WRITE_TIMEOUT           = 12
  OPT_USE_RESULT              = 13
  OPT_USE_REMOTE_CONNECTION   = 14
  OPT_USE_EMBEDDED_CONNECTION = 15
  OPT_GUESS_CONNECTION        = 16
  SET_CLIENT_IP               = 17
  SECURE_AUTH                 = 18
  REPORT_DATA_TRUNCATION      = 19
  OPT_RECONNECT               = 20
  OPT_SSL_VERIFY_SERVER_CERT  = 21

  # Server Option
  OPTION_MULTI_STATEMENTS_ON  = 0
  OPTION_MULTI_STATEMENTS_OFF = 1

  # Server Status
  SERVER_STATUS_IN_TRANS             = 1
  SERVER_STATUS_AUTOCOMMIT           = 1 << 1
  SERVER_MORE_RESULTS_EXISTS         = 1 << 3
  SERVER_QUERY_NO_GOOD_INDEX_USED    = 1 << 4
  SERVER_QUERY_NO_INDEX_USED         = 1 << 5
  SERVER_STATUS_CURSOR_EXISTS        = 1 << 6
  SERVER_STATUS_LAST_ROW_SENT        = 1 << 7
  SERVER_STATUS_DB_DROPPED           = 1 << 8
  SERVER_STATUS_NO_BACKSLASH_ESCAPES = 1 << 9

  # Refresh parameter
  REFRESH_GRANT     = 1
  REFRESH_LOG       = 1 << 1
  REFRESH_TABLES    = 1 << 2
  REFRESH_HOSTS     = 1 << 3
  REFRESH_STATUS    = 1 << 4
  REFRESH_THREADS   = 1 << 5
  REFRESH_SLAVE     = 1 << 6
  REFRESH_MASTER    = 1 << 7
  REFRESH_READ_LOCK = 1 << 14
  REFRESH_FAST      = 1 << 15

  class Field
    # Field type
    TYPE_DECIMAL     = 0
    TYPE_TINY        = 1
    TYPE_SHORT       = 2
    TYPE_LONG        = 3
    TYPE_FLOAT       = 4
    TYPE_DOUBLE      = 5
    TYPE_NULL        = 6
    TYPE_TIMESTAMP   = 7
    TYPE_LONGLONG    = 8
    TYPE_INT24       = 9
    TYPE_DATE        = 10
    TYPE_TIME        = 11
    TYPE_DATETIME    = 12
    TYPE_YEAR        = 13
    TYPE_NEWDATE     = 14
    TYPE_VARCHAR     = 15
    TYPE_BIT         = 16
    TYPE_NEWDECIMAL  = 246
    TYPE_ENUM        = 247
    TYPE_SET         = 248
    TYPE_TINY_BLOB   = 249
    TYPE_MEDIUM_BLOB = 250
    TYPE_LONG_BLOB   = 251
    TYPE_BLOB        = 252
    TYPE_VAR_STRING  = 253
    TYPE_STRING      = 254
    TYPE_GEOMETRY    = 255
    TYPE_CHAR        = TYPE_TINY
    TYPE_INTERVAL    = TYPE_ENUM

    # Flag
    NOT_NULL_FLAG       = 1
    PRI_KEY_FLAG        = 2
    UNIQUE_KEY_FLAG     = 4
    MULTIPLE_KEY_FLAG   = 8
    BLOB_FLAG           = 16
    UNSIGNED_FLAG       = 32
    ZEROFILL_FLAG       = 64
    BINARY_FLAG         = 128
    ENUM_FLAG           = 256
    AUTO_INCREMENT_FLAG = 512
    TIMESTAMP_FLAG      = 1024
    SET_FLAG            = 2048
    NUM_FLAG            = 32768
    PART_KEY_FLAG       = 16384
    GROUP_FLAG          = 32768
    UNIQUE_FLAG         = 65536
    BINCMP_FLAG         = 131072
  end

  class Statement
    # Cursor type
    CURSOR_TYPE_NO_CURSOR = 0
    CURSOR_TYPE_READ_ONLY = 1
  end
end

