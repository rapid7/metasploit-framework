require 'sqlite3/errors'

module SQLite3

  # This module is intended for inclusion solely by the Database class. It
  # defines convenience methods for the various pragmas supported by SQLite3.
  #
  # For a detailed description of these pragmas, see the SQLite3 documentation
  # at http://sqlite.org/pragma.html.
  module Pragmas

    # Returns +true+ or +false+ depending on the value of the named pragma.
    def get_boolean_pragma( name )
      get_first_value( "PRAGMA #{name}" ) != "0"
    end

    # Sets the given pragma to the given boolean value. The value itself
    # may be +true+ or +false+, or any other commonly used string or
    # integer that represents truth.
    def set_boolean_pragma( name, mode )
      case mode
        when String
          case mode.downcase
            when "on", "yes", "true", "y", "t"; mode = "'ON'"
            when "off", "no", "false", "n", "f"; mode = "'OFF'"
            else
              raise Exception,
                "unrecognized pragma parameter #{mode.inspect}"
          end
        when true, 1
          mode = "ON"
        when false, 0, nil
          mode = "OFF"
        else
          raise Exception,
            "unrecognized pragma parameter #{mode.inspect}"
      end

      execute( "PRAGMA #{name}=#{mode}" )
    end

    # Requests the given pragma (and parameters), and if the block is given,
    # each row of the result set will be yielded to it. Otherwise, the results
    # are returned as an array.
    def get_query_pragma( name, *parms, &block ) # :yields: row
      if parms.empty?
        execute( "PRAGMA #{name}", &block )
      else
        args = "'" + parms.join("','") + "'"
        execute( "PRAGMA #{name}( #{args} )", &block )
      end
    end

    # Return the value of the given pragma.
    def get_enum_pragma( name )
      get_first_value( "PRAGMA #{name}" )
    end

    # Set the value of the given pragma to +mode+. The +mode+ parameter must
    # conform to one of the values in the given +enum+ array. Each entry in
    # the array is another array comprised of elements in the enumeration that
    # have duplicate values. See #synchronous, #default_synchronous,
    # #temp_store, and #default_temp_store for usage examples.
    def set_enum_pragma( name, mode, enums )
      match = enums.find { |p| p.find { |i| i.to_s.downcase == mode.to_s.downcase } }
      raise Exception,
        "unrecognized #{name} #{mode.inspect}" unless match
      execute( "PRAGMA #{name}='#{match.first.upcase}'" )
    end

    # Returns the value of the given pragma as an integer.
    def get_int_pragma( name )
      get_first_value( "PRAGMA #{name}" ).to_i
    end

    # Set the value of the given pragma to the integer value of the +value+
    # parameter.
    def set_int_pragma( name, value )
      execute( "PRAGMA #{name}=#{value.to_i}" )
    end

    # The enumeration of valid synchronous modes.
    SYNCHRONOUS_MODES = [ [ 'full', 2 ], [ 'normal', 1 ], [ 'off', 0 ] ]

    # The enumeration of valid temp store modes.
    TEMP_STORE_MODES  = [ [ 'default', 0 ], [ 'file', 1 ], [ 'memory', 2 ] ]

    # The enumeration of valid auto vacuum modes.
    AUTO_VACUUM_MODES  = [ [ 'none', 0 ], [ 'full', 1 ], [ 'incremental', 2 ] ]

    # The list of valid journaling modes.
    JOURNAL_MODES  = [ [ 'delete' ], [ 'truncate' ], [ 'persist' ], [ 'memory' ],
                       [ 'wal' ], [ 'off' ] ]

    # The list of valid locking modes.
    LOCKING_MODES  = [ [ 'normal' ], [ 'exclusive' ] ]

    # The list of valid encodings.
    ENCODINGS = [ [ 'utf-8' ], [ 'utf-16' ], [ 'utf-16le' ], [ 'utf-16be ' ] ]

    # The list of valid WAL checkpoints.
    WAL_CHECKPOINTS = [ [ 'passive' ], [ 'full' ], [ 'restart' ], [ 'truncate' ] ]

    def application_id
      get_int_pragma "application_id"
    end

    def application_id=( integer )
      set_int_pragma "application_id", integer
    end

    def auto_vacuum
      get_enum_pragma "auto_vacuum"
    end

    def auto_vacuum=( mode )
      set_enum_pragma "auto_vacuum", mode, AUTO_VACUUM_MODES
    end

    def automatic_index
      get_boolean_pragma "automatic_index"
    end

    def automatic_index=( mode )
      set_boolean_pragma "automatic_index", mode
    end

    def busy_timeout
      get_int_pragma "busy_timeout"
    end

    def busy_timeout=( milliseconds )
      set_int_pragma "busy_timeout", milliseconds
    end

    def cache_size
      get_int_pragma "cache_size"
    end

    def cache_size=( size )
      set_int_pragma "cache_size", size
    end

    def cache_spill
      get_boolean_pragma "cache_spill"
    end

    def cache_spill=( mode )
      set_boolean_pragma "cache_spill", mode
    end

    def case_sensitive_like=( mode )
      set_boolean_pragma "case_sensitive_like", mode
    end

    def cell_size_check
      get_boolean_pragma "cell_size_check"
    end

    def cell_size_check=( mode )
      set_boolean_pragma "cell_size_check", mode
    end

    def checkpoint_fullfsync
      get_boolean_pragma "checkpoint_fullfsync"
    end

    def checkpoint_fullfsync=( mode )
      set_boolean_pragma "checkpoint_fullfsync", mode
    end

    def collation_list( &block ) # :yields: row
      get_query_pragma "collation_list", &block
    end

    def compile_options( &block ) # :yields: row
      get_query_pragma "compile_options", &block
    end

    def count_changes
      get_boolean_pragma "count_changes"
    end

    def count_changes=( mode )
      set_boolean_pragma "count_changes", mode
    end

    def data_version
      get_int_pragma "data_version"
    end

    def database_list( &block ) # :yields: row
      get_query_pragma "database_list", &block
    end

    def default_cache_size
      get_int_pragma "default_cache_size"
    end

    def default_cache_size=( size )
      set_int_pragma "default_cache_size", size
    end

    def default_synchronous
      get_enum_pragma "default_synchronous"
    end

    def default_synchronous=( mode )
      set_enum_pragma "default_synchronous", mode, SYNCHRONOUS_MODES
    end

    def default_temp_store
      get_enum_pragma "default_temp_store"
    end

    def default_temp_store=( mode )
      set_enum_pragma "default_temp_store", mode, TEMP_STORE_MODES
    end

    def defer_foreign_keys
      get_boolean_pragma "defer_foreign_keys"
    end

    def defer_foreign_keys=( mode )
      set_boolean_pragma "defer_foreign_keys", mode
    end

    def encoding
      get_enum_pragma "encoding"
    end

    def encoding=( mode )
      set_enum_pragma "encoding", mode, ENCODINGS
    end

    def foreign_key_check( *table, &block ) # :yields: row
      get_query_pragma "foreign_key_check", *table, &block
    end

    def foreign_key_list( table, &block ) # :yields: row
      get_query_pragma "foreign_key_list", table, &block
    end

    def foreign_keys
      get_boolean_pragma "foreign_keys"
    end

    def foreign_keys=( mode )
      set_boolean_pragma "foreign_keys", mode
    end

    def freelist_count
      get_int_pragma "freelist_count"
    end

    def full_column_names
      get_boolean_pragma "full_column_names"
    end

    def full_column_names=( mode )
      set_boolean_pragma "full_column_names", mode
    end
  
    def fullfsync
      get_boolean_pragma "fullfsync"
    end

    def fullfsync=( mode )
      set_boolean_pragma "fullfsync", mode
    end

    def ignore_check_constraints=( mode )
      set_boolean_pragma "ignore_check_constraints", mode
    end

    def incremental_vacuum( pages, &block ) # :yields: row
      get_query_pragma "incremental_vacuum", pages, &block
    end

    def index_info( index, &block ) # :yields: row
      get_query_pragma "index_info", index, &block
    end

    def index_list( table, &block ) # :yields: row
      get_query_pragma "index_list", table, &block
    end

    def index_xinfo( index, &block ) # :yields: row
      get_query_pragma "index_xinfo", index, &block
    end

    def integrity_check( *num_errors, &block ) # :yields: row
      get_query_pragma "integrity_check", *num_errors, &block
    end

    def journal_mode
      get_enum_pragma "journal_mode"
    end

    def journal_mode=( mode )
      set_enum_pragma "journal_mode", mode, JOURNAL_MODES
    end

    def journal_size_limit
      get_int_pragma "journal_size_limit"
    end

    def journal_size_limit=( size )
      set_int_pragma "journal_size_limit", size
    end

    def legacy_file_format
      get_boolean_pragma "legacy_file_format"
    end

    def legacy_file_format=( mode )
      set_boolean_pragma "legacy_file_format", mode
    end

    def locking_mode
      get_enum_pragma "locking_mode"
    end

    def locking_mode=( mode )
      set_enum_pragma "locking_mode", mode, LOCKING_MODES
    end

    def max_page_count
      get_int_pragma "max_page_count"
    end

    def max_page_count=( size )
      set_int_pragma "max_page_count", size
    end

    def mmap_size
      get_int_pragma "mmap_size"
    end

    def mmap_size=( size )
      set_int_pragma "mmap_size", size
    end

    def page_count
      get_int_pragma "page_count"
    end

    def page_size
      get_int_pragma "page_size"
    end

    def page_size=( size )
      set_int_pragma "page_size", size
    end

    def parser_trace=( mode )
      set_boolean_pragma "parser_trace", mode
    end
  
    def query_only
      get_boolean_pragma "query_only"
    end

    def query_only=( mode )
      set_boolean_pragma "query_only", mode
    end

    def quick_check( *num_errors, &block ) # :yields: row
      get_query_pragma "quick_check", *num_errors, &block
    end

    def read_uncommitted
      get_boolean_pragma "read_uncommitted"
    end

    def read_uncommitted=( mode )
      set_boolean_pragma "read_uncommitted", mode
    end

    def recursive_triggers
      get_boolean_pragma "recursive_triggers"
    end

    def recursive_triggers=( mode )
      set_boolean_pragma "recursive_triggers", mode
    end

    def reverse_unordered_selects
      get_boolean_pragma "reverse_unordered_selects"
    end

    def reverse_unordered_selects=( mode )
      set_boolean_pragma "reverse_unordered_selects", mode
    end

    def schema_cookie
      get_int_pragma "schema_cookie"
    end

    def schema_cookie=( cookie )
      set_int_pragma "schema_cookie", cookie
    end

    def schema_version
      get_int_pragma "schema_version"
    end

    def schema_version=( version )
      set_int_pragma "schema_version", version
    end

    def secure_delete
      get_boolean_pragma "secure_delete"
    end

    def secure_delete=( mode )
      set_boolean_pragma "secure_delete", mode
    end

    def short_column_names
      get_boolean_pragma "short_column_names"
    end

    def short_column_names=( mode )
      set_boolean_pragma "short_column_names", mode
    end

    def shrink_memory
      execute( "PRAGMA shrink_memory" )
    end

    def soft_heap_limit
      get_int_pragma "soft_heap_limit"
    end

    def soft_heap_limit=( mode )
      set_int_pragma "soft_heap_limit", mode
    end

    def stats( &block ) # :yields: row
      get_query_pragma "stats", &block
    end

    def synchronous
      get_enum_pragma "synchronous"
    end

    def synchronous=( mode )
      set_enum_pragma "synchronous", mode, SYNCHRONOUS_MODES
    end

    def temp_store
      get_enum_pragma "temp_store"
    end

    def temp_store=( mode )
      set_enum_pragma "temp_store", mode, TEMP_STORE_MODES
    end

    def threads
      get_int_pragma "threads"
    end

    def threads=( count )
      set_int_pragma "threads", count
    end

    def user_cookie
      get_int_pragma "user_cookie"
    end

    def user_cookie=( cookie )
      set_int_pragma "user_cookie", cookie
    end

    def user_version
      get_int_pragma "user_version"
    end

    def user_version=( version )
      set_int_pragma "user_version", version
    end

    def vdbe_addoptrace=( mode )
      set_boolean_pragma "vdbe_addoptrace", mode
    end

    def vdbe_debug=( mode )
      set_boolean_pragma "vdbe_debug", mode
    end

    def vdbe_listing=( mode )
      set_boolean_pragma "vdbe_listing", mode
    end

    def vdbe_trace
      get_boolean_pragma "vdbe_trace"
    end

    def vdbe_trace=( mode )
      set_boolean_pragma "vdbe_trace", mode
    end

    def wal_autocheckpoint
      get_int_pragma "wal_autocheckpoint"
    end

    def wal_autocheckpoint=( mode )
      set_int_pragma "wal_autocheckpoint", mode
    end

    def wal_checkpoint
      get_enum_pragma "wal_checkpoint"
    end

    def wal_checkpoint=( mode )
      set_enum_pragma "wal_checkpoint", mode, WAL_CHECKPOINTS
    end

    def writable_schema=( mode )
      set_boolean_pragma "writable_schema", mode
    end

    ###
    # Returns information about +table+.  Yields each row of table information
    # if a block is provided.
    def table_info table
      stmt    = prepare "PRAGMA table_info(#{table})"
      columns = stmt.columns

      needs_tweak_default =
        version_compare(SQLite3.libversion.to_s, "3.3.7") > 0

      result = [] unless block_given?
      stmt.each do |row|
        new_row = Hash[columns.zip(row)]

        # FIXME: This should be removed but is required for older versions
        # of rails
        if(Object.const_defined?(:ActiveRecord))
          new_row['notnull'] = new_row['notnull'].to_s
        end

        tweak_default(new_row) if needs_tweak_default

        if block_given?
          yield new_row
        else
          result << new_row
        end
      end
      stmt.close

      result
    end

    private

      # Compares two version strings
      def version_compare(v1, v2)
        v1 = v1.split(".").map { |i| i.to_i }
        v2 = v2.split(".").map { |i| i.to_i }
        parts = [v1.length, v2.length].max
        v1.push 0 while v1.length < parts
        v2.push 0 while v2.length < parts
        v1.zip(v2).each do |a,b|
          return -1 if a < b
          return  1 if a > b
        end
        return 0
      end

      # Since SQLite 3.3.8, the table_info pragma has returned the default
      # value of the row as a quoted SQL value. This method essentially
      # unquotes those values.
      def tweak_default(hash)
        case hash["dflt_value"]
        when /^null$/i
          hash["dflt_value"] = nil
        when /^'(.*)'$/m
          hash["dflt_value"] = $1.gsub(/''/, "'")
        when /^"(.*)"$/m
          hash["dflt_value"] = $1.gsub(/""/, '"')
        end
      end
  end

end
