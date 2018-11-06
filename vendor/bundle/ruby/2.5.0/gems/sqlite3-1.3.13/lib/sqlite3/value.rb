require 'sqlite3/constants'

module SQLite3

  class Value
    attr_reader :handle

    def initialize( db, handle )
      @driver = db.driver
      @handle = handle
    end

    def null?
      type == :null
    end

    def to_blob
      @driver.value_blob( @handle )
    end

    def length( utf16=false )
      if utf16
        @driver.value_bytes16( @handle )
      else
        @driver.value_bytes( @handle )
      end
    end

    def to_f
      @driver.value_double( @handle )
    end

    def to_i
      @driver.value_int( @handle )
    end

    def to_int64
      @driver.value_int64( @handle )
    end

    def to_s( utf16=false )
      @driver.value_text( @handle, utf16 )
    end

    def type
      case @driver.value_type( @handle )
        when Constants::ColumnType::INTEGER then :int
        when Constants::ColumnType::FLOAT   then :float
        when Constants::ColumnType::TEXT    then :text
        when Constants::ColumnType::BLOB    then :blob
        when Constants::ColumnType::NULL    then :null
      end
    end
    
  end

end
