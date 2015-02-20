# -*- coding: binary -*-
# Copyright (C) 2008 TOMITA Masahiro
# mailto:tommy@tmtm.org

# for compatibility

class RbMysql
  class << self

    def connect(*args)
      my = self.allocate
      my.instance_eval{initialize}
      my.connect(*args)
      my
    end
    alias new connect
    alias real_connect connect

    def init
      my = self.allocate
      my.instance_eval{initialize}
      my
    end

    def client_version
      50067
    end

    def client_info
      "5.0.67"
    end
    alias get_client_info client_info

    def escape_string(str)
      str.gsub(/[\0\n\r\\\'\"\x1a]/n) do |s|
        case s
        when "\0" then "\\0"
        when "\n" then "\\n"
        when "\r" then "\\r"
        when "\x1a" then "\\Z"
        else "\\#{s}"
        end
      end
    end
    alias quote escape_string
  end

  attr_accessor :query_with_result, :reconnect

  alias stmt_init statement
  alias real_connect connect
  alias initialize_orig initialize

  def initialize(*args)
    initialize_orig(*args)
    @query_with_result = true
    @reconnect = false
  end

  def query(str)
    res = simple_query str
    if res
      res.each do |rec|
        rec.map!{|v| v && v.to_s}
        rec.each_index do |i|
          @fields[i].max_length = [rec[i] ? rec[i].length : 0, @fields[i].max_length||0].max
        end
      end
      res.data_seek 0
    end
    res
  end

  def client_version
    self.class.client_version
  end

  def options(opt, val=nil)
    case opt
    when INIT_COMMAND
      @init_command = val
    when OPT_COMPRESS
      raise ClientError, "not implemented"
    when OPT_CONNECT_TIMEOUT
      @connect_timeout = val
    when OPT_GUESS_CONNECTION
      raise ClientError, "not implemented"
    when OPT_LOCAL_INFILE
      @local_infile = val
    when OPT_NAMED_PIPE
      raise ClientError, "not implemented"
    when OPT_PROTOCOL
      raise ClientError, "not implemented"
    when OPT_READ_TIMEOUT
      @read_timeout = val
    when OPT_USE_EMBEDDED_CONNECTION
      raise ClientError, "not implemented"
    when OPT_USE_REMOTE_CONNECTION
      raise ClientError, "not implemented"
    when OPT_WRITE_TIMEOUT
      @write_timeout = val
    when READ_DEFAULT_FILE
      raise ClientError, "not implemented"
    when READ_DEFAULT_GROUP
      raise ClientError, "not implemented"
    when SECURE_AUTH
      raise ClientError, "not implemented"
    when SET_CHARSET_DIR
      raise ClientError, "not implemented"
    when SET_CHARSET_NAME
      self.charset = val
    when SET_CLIENT_IP
      raise ClientError, "not implemented"
    when SHARED_MEMORY_BASE_NAME
      raise ClientError, "not implemented"
    else
      raise ClientError, "unknown option: #{opt}"
    end
    self
  end

  def store_result
    raise ClientError, "no result set" unless @fields
    Result.new @fields, @stream
  end

  def use_result
    raise ClientError, "no result set" unless @fields
    Result.new @fields, @stream, false
  end

  class Result
    alias initialize_orig initialize
    def initialize(*args)
      initialize_orig *args
      @field_index = 0
    end

    def num_rows
      @records.length
    end

    def data_seek(n)
      @index = n
    end

    def row_tell
      @index
    end

    def row_seek(n)
      ret = @index
      @index = n
      ret
    end

    def free
      # do nothing
    end

    alias fetch_row_orig fetch_row
    def fetch_row
      @fetched_record = fetch_row_orig
    end

    def fetch_field
      return nil if @field_index >= @fields.length
      ret = @fields[@field_index]
      @field_index += 1
      ret
    end

    def field_tell
      @field_index
    end

    def field_seek(n)
      @field_index = n
    end

    def fetch_field_direct(n)
      raise ClientError, "invalid argument: #{n}" if n < 0 or n >= @fields.length
      @fields[n]
    end

    def fetch_fields
      @fields
    end

    def fetch_lengths
      return nil unless @fetched_record
      @fetched_record.map{|c|c.nil? ? 0 : c.length}
    end

    def num_fields
      @fields.length
    end
  end

  class Field
    attr_accessor :max_length
    def hash
      {
        "name"       => @name,
        "table"      => @table,
        "def"        => @default,
        "type"       => @type,
        "length"     => @length,
        "max_length" => @max_length,
        "flags"      => @flags,
        "decimals"   => @decimals
      }
    end
    def inspect
      "#<RbMysql::Field:#{@name}>"
    end
  end

  class Statement
    alias execute_orig execute
    def execute(*args)
      @res = execute_orig *args
    end

    def fetch
      @res.fetch
    end
    alias fetch_row fetch

    def each(*args, &block)
      @res.each(*args, &block)
    end

    def num_rows
      @res.num_rows
    end

    def data_seek(n)
      @res.data_seek(n)
    end

    def row_tell
      @res.row_tell
    end

    def row_seek(n)
      @res.row_seek(n)
    end

    def field_count
      @fields.length
    end

    def free_result
      # do nothing
    end

    def result_metadata
      return nil if @fields.empty?
      res = Result.allocate
      res.instance_variable_set :@mysql, @mysql
      res.instance_variable_set :@fields, @fields
      res.instance_variable_set :@records, []
      res
    end
  end
  Stmt = Statement
end

