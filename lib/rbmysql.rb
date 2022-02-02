# coding: ascii-8bit
# Copyright (C) 2008-2012 TOMITA Masahiro
# mailto:tommy@tmtm.org

# MySQL connection class.
# @example
#  my = RbMysql.connect('hostname', 'user', 'password', 'dbname')
#  res = my.query 'select col1,col2 from tbl where id=123'
#  res.each do |c1, c2|
#    p c1, c2
#  end
class RbMysql

  require "rbmysql/constants"
  require "rbmysql/error"
  require "rbmysql/charset"
  require "rbmysql/protocol"
  require "rbmysql/packet.rb"
  begin
    require "mysql/ext.so"
  rescue LoadError
  end

  VERSION            = 20913               # Version number of this library
  MYSQL_UNIX_PORT    = "/tmp/mysql.sock"   # UNIX domain socket filename
  MYSQL_TCP_PORT     = 3306                # TCP socket port number

  # @return [RbMysql::Charset] character set of MySQL connection
  attr_reader :charset
  # @private
  attr_reader :protocol

  # @return [Boolean] if true, {#query} return {RbMysql::Result}.
  attr_accessor :query_with_result

  class << self
    # Make RbMysql object without connecting.
    # @return [RbMysql]
    def init
      my = self.allocate
      my.instance_eval{initialize}
      my
    end

    # Make RbMysql object and connect to mysqld.
    # @param args same as arguments for {#connect}.
    # @return [RbMysql]
    def new(*args)
      my = self.init
      my.connect(*args)
    end

    alias real_connect new
    alias connect new

    # Escape special character in string.
    # @param [String] str
    # @return [String]
    def escape_string(str)
      str.gsub(/[\0\n\r\\\'\"\x1a]/) do |s|
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

    # @return [String] client version. This value is dummy for MySQL/Ruby compatibility.
    def client_info
      "5.0.0"
    end
    alias get_client_info client_info

    # @return [Integer] client version. This value is dummy for MySQL/Ruby compatibility.
    def client_version
      50000
    end
    alias get_client_version client_version
  end

  def initialize
    @fields = nil
    @protocol = nil
    @charset = nil
    @connect_timeout = nil
    @read_timeout = nil
    @write_timeout = nil
    @init_command = nil
    @sqlstate = "00000"
    @query_with_result = true
    @host_info = nil
    @last_error = nil
    @result_exist = false
    @local_infile = nil
  end

  # Connect to mysqld.
  # @param [String / nil] host hostname mysqld running
  # @param [String / nil] user username to connect to mysqld
  # @param [String / nil] passwd password to connect to mysqld
  # @param [String / nil] db initial database name
  # @param [Integer / nil] port port number (used if host is not 'localhost' or nil)
  # @param [String / nil] socket socket file name (used if host is 'localhost' or nil)
  # @param [Integer / nil] flag connection flag. RbMysql::CLIENT_* ORed
  # @return self
  def connect(host=nil, user=nil, passwd=nil, db=nil, port=nil, socket=nil, flag=0)
    if flag & CLIENT_COMPRESS != 0
      warn 'unsupported flag: CLIENT_COMPRESS' if $VERBOSE
      flag &= ~CLIENT_COMPRESS
    end
    @protocol = Protocol.new host, port, socket, @connect_timeout, @read_timeout, @write_timeout
    @protocol.authenticate user, passwd, db, (@local_infile ? CLIENT_LOCAL_FILES : 0) | flag, @charset
    @charset ||= @protocol.charset
    @host_info = (host.nil? || host == "localhost") ? 'Localhost via UNIX socket' : "#{host} via TCP/IP"
    query @init_command if @init_command
    return self
  end
  alias real_connect connect

  # Disconnect from mysql.
  # @return [RbMysql] self
  def close
    if @protocol
      @protocol.quit_command
      @protocol = nil
    end
    return self
  end

  # Disconnect from mysql without QUIT packet.
  # @return [RbMysql] self
  def close!
    if @protocol
      @protocol.close
      @protocol = nil
    end
    return self
  end

  # Set option for connection.
  #
  # Available options:
  #   RbMysql::INIT_COMMAND, RbMysql::OPT_CONNECT_TIMEOUT, RbMysql::OPT_READ_TIMEOUT,
  #   RbMysql::OPT_WRITE_TIMEOUT, RbMysql::SET_CHARSET_NAME
  # @param [Integer] opt option
  # @param [Integer] value option value that is depend on opt
  # @return [RbMysql] self
  def options(opt, value=nil)
    case opt
    when RbMysql::INIT_COMMAND
      @init_command = value.to_s
      #    when RbMysql::OPT_COMPRESS
    when RbMysql::OPT_CONNECT_TIMEOUT
      @connect_timeout = value
      #    when RbMysql::GUESS_CONNECTION
    when RbMysql::OPT_LOCAL_INFILE
      @local_infile = value
      #    when RbMysql::OPT_NAMED_PIPE
      #    when RbMysql::OPT_PROTOCOL
    when RbMysql::OPT_READ_TIMEOUT
      @read_timeout = value.to_i
      #    when RbMysql::OPT_RECONNECT
      #    when RbMysql::SET_CLIENT_IP
      #    when RbMysql::OPT_SSL_VERIFY_SERVER_CERT
      #    when RbMysql::OPT_USE_EMBEDDED_CONNECTION
      #    when RbMysql::OPT_USE_REMOTE_CONNECTION
    when RbMysql::OPT_WRITE_TIMEOUT
      @write_timeout = value.to_i
      #    when RbMysql::READ_DEFAULT_FILE
      #    when RbMysql::READ_DEFAULT_GROUP
      #    when RbMysql::REPORT_DATA_TRUNCATION
      #    when RbMysql::SECURE_AUTH
      #    when RbMysql::SET_CHARSET_DIR
    when RbMysql::SET_CHARSET_NAME
      @charset = Charset.by_name value.to_s
      #    when RbMysql::SHARED_MEMORY_BASE_NAME
    else
      warn "option not implemented: #{opt}" if $VERBOSE
    end
    self
  end

  # Escape special character in MySQL.
  #
  # In Ruby 1.8, this is not safe for multibyte charset such as 'SJIS'.
  # You should use place-holder in prepared-statement.
  # @param [String] str
  # return [String]
  def escape_string(str)
    if not defined? Encoding and @charset.unsafe
      raise ClientError, 'RbMysql#escape_string is called for unsafe multibyte charset'
    end
    self.class.escape_string str
  end
  alias quote escape_string

  # @return [String] client version
  def client_info
    self.class.client_info
  end
  alias get_client_info client_info

  # @return [Integer] client version
  def client_version
    self.class.client_version
  end
  alias get_client_version client_version

  # Set charset of MySQL connection.
  # @param [String / RbMysql::Charset] cs
  def charset=(cs)
    charset = cs.is_a?(Charset) ? cs : Charset.by_name(cs)
    if @protocol
      @protocol.charset = charset
      query "SET NAMES #{charset.name}"
    end
    @charset = charset
    cs
  end

  # @return [String] charset name
  def character_set_name
    @charset.name
  end

  # @return [Integer] last error number
  def errno
    @last_error ? @last_error.errno : 0
  end

  # @return [String] last error message
  def error
    @last_error && @last_error.error
  end

  # @return [String] sqlstate for last error
  def sqlstate
    @last_error ? @last_error.sqlstate : "00000"
  end

  # @return [Integer] number of columns for last query
  def field_count
    @fields.size
  end

  # @return [String] connection type
  def host_info
    @host_info
  end
  alias get_host_info host_info

  # @return [Integer] protocol version
  def proto_info
    RbMysql::Protocol::VERSION
  end
  alias get_proto_info proto_info

  # @return [String] server version
  def server_info
    check_connection
    @protocol.server_info
  end
  alias get_server_info server_info

  # @return [Integer] server version
  def server_version
    check_connection
    @protocol.server_version
  end
  alias get_server_version server_version

  # @return [String] information for last query
  def info
    @protocol && @protocol.message
  end

  # @return [Integer] number of affected records by insert/update/delete.
  def affected_rows
    @protocol ? @protocol.affected_rows : 0
  end

  # @return [Integer] latest auto_increment value
  def insert_id
    @protocol ? @protocol.insert_id : 0
  end

  # @return [Integer] number of warnings for previous query
  def warning_count
    @protocol ? @protocol.warning_count : 0
  end

  # Kill query.
  # @param [Integer] pid thread id
  # @return [RbMysql] self
  def kill(pid)
    check_connection
    @protocol.kill_command pid
    self
  end

  # database list.
  # @param [String] db database name that may contain wild card.
  # @return [Array<String>] database list
  def list_dbs(db=nil)
    db &&= db.gsub(/[\\\']/){"\\#{$&}"}
    query(db ? "show databases like '#{db}'" : "show databases").map(&:first)
  end

  # Execute query string.
  # @param [String] str Query.
  # @yield [RbMysql::Result] evaluated per query.
  # @return [RbMysql::Result] If {#query_with_result} is true and result set exist.
  # @return [nil] If {#query_with_result} is true and the query does not return result set.
  # @return [RbMysql] If {#query_with_result} is false or block is specified
  # @example
  #  my.query("select 1,NULL,'abc'").fetch  # => [1, nil, "abc"]
  def query(str, &block)
    check_connection
    @fields = nil
    begin
      nfields = @protocol.query_command str
      if nfields
        @fields = @protocol.retr_fields nfields
        @result_exist = true
      end
      if block
        while true
          block.call store_result if @fields
          break unless next_result
        end
        return self
      end
      if @query_with_result
        return @fields ? store_result : nil
      else
        return self
      end
    rescue ServerError => e
      @last_error = e
      @sqlstate = e.sqlstate
      raise
    end
  end
  alias real_query query

  # Get all data for last query if query_with_result is false.
  # @return [RbMysql::Result]
  def store_result
    check_connection
    raise ClientError, 'invalid usage' unless @result_exist
    res = Result.new @fields, @protocol
    @result_exist = false
    res
  end

  # @return [Integer] Thread ID
  def thread_id
    check_connection
    @protocol.thread_id
  end

  # Use result of query. The result data is retrieved when you use RbMysql::Result#fetch.
  # @return [RbMysql::Result]
  def use_result
    store_result
  end

  # Set server option.
  # @param [Integer] opt {RbMysql::OPTION_MULTI_STATEMENTS_ON} or {RbMysql::OPTION_MULTI_STATEMENTS_OFF}
  # @return [RbMysql] self
  def set_server_option(opt)
    check_connection
    @protocol.set_option_command opt
    self
  end

  # @return [Boolean] true if multiple queries are specified and unexecuted queries exists.
  def more_results
    @protocol.server_status & SERVER_MORE_RESULTS_EXISTS != 0
  end
  alias more_results? more_results

  # execute next query if multiple queries are specified.
  # @return [Boolean] true if next query exists.
  def next_result
    return false unless more_results
    check_connection
    @fields = nil
    nfields = @protocol.get_result
    if nfields
      @fields = @protocol.retr_fields nfields
      @result_exist = true
    end
    return true
  end

  # Parse prepared-statement.
  # @param [String] str query string
  # @return [RbMysql::Stmt] Prepared-statement object
  def prepare(str)
    st = Stmt.new @protocol, @charset
    st.prepare str
    st
  end

  # @private
  # Make empty prepared-statement object.
  # @return [RbMysql::Stmt] If block is not specified.
  def stmt_init
    Stmt.new @protocol, @charset
  end

  # Returns RbMysql::Result object that is empty.
  # Use fetch_fields to get list of fields.
  # @param [String] table table name.
  # @param [String] field field name that may contain wild card.
  # @return [RbMysql::Result]
  def list_fields(table, field=nil)
    check_connection
    begin
      fields = @protocol.field_list_command table, field
      return Result.new fields
    rescue ServerError => e
      @last_error = e
      @sqlstate = e.sqlstate
      raise
    end
  end

  # @return [RbMysql::Result] containing process list
  def list_processes
    check_connection
    @fields = @protocol.process_info_command
    @result_exist = true
    store_result
  end

  # @note for Ruby 1.8: This is not multi-byte safe. Don't use for multi-byte charset such as cp932.
  # @param [String] table database name that may contain wild card.
  # @return [Array<String>] list of table name.
  def list_tables(table=nil)
    q = table ? "show tables like '#{quote table}'" : "show tables"
    query(q).map(&:first)
  end

  # Check whether the  connection is available.
  # @return [RbMysql] self
  def ping
    check_connection
    @protocol.ping_command
    self
  end

  # Flush tables or caches.
  # @param [Integer] op operation. Use RbMysql::REFRESH_* value.
  # @return [RbMysql] self
  def refresh(op)
    check_connection
    @protocol.refresh_command op
    self
  end

  # Reload grant tables.
  # @return [RbMysql] self
  def reload
    refresh RbMysql::REFRESH_GRANT
  end

  # Select default database
  # @return [RbMysql] self
  def select_db(db)
    query "use #{db}"
    self
  end

  # shutdown server.
  # @return [RbMysql] self
  def shutdown(level=0)
    check_connection
    @protocol.shutdown_command level
    self
  end

  # @return [String] statistics message
  def stat
    @protocol ? @protocol.statistics_command : 'MySQL server has gone away'
  end

  # Commit transaction
  # @return [RbMysql] self
  def commit
    query 'commit'
    self
  end

  # Rollback transaction
  # @return [RbMysql] self
  def rollback
    query 'rollback'
    self
  end

  # Set autocommit mode
  # @param [Boolean] flag
  # @return [RbMysql] self
  def autocommit(flag)
    query "set autocommit=#{flag ? 1 : 0}"
    self
  end

  private

  def check_connection
    raise ClientError::ServerGoneError, 'MySQL server has gone away' unless @protocol
  end

  # @!visibility public
  # Field class
  class Field
    # @return [String] database name
    attr_reader :db
    # @return [String] table name
    attr_reader :table
    # @return [String] original table name
    attr_reader :org_table
    # @return [String] field name
    attr_reader :name
    # @return [String] original field name
    attr_reader :org_name
    # @return [Integer] charset id number
    attr_reader :charsetnr
    # @return [Integer] field length
    attr_reader :length
    # @return [Integer] field type
    attr_reader :type
    # @return [Integer] flag
    attr_reader :flags
    # @return [Integer] number of decimals
    attr_reader :decimals
    # @return [String] defualt value
    attr_reader :default
    alias :def :default

    # @private
    attr_accessor :result

    # @attr [Protocol::FieldPacket] packet
    def initialize(packet)
      @db, @table, @org_table, @name, @org_name, @charsetnr, @length, @type, @flags, @decimals, @default =
        packet.db, packet.table, packet.org_table, packet.name, packet.org_name, packet.charsetnr, packet.length, packet.type, packet.flags, packet.decimals, packet.default
      @flags |= NUM_FLAG if is_num_type?
      @max_length = nil
    end

    # @return [Hash] field information
    def hash
      {
        "name"       => @name,
        "table"      => @table,
        "def"        => @default,
        "type"       => @type,
        "length"     => @length,
        "max_length" => max_length,
        "flags"      => @flags,
        "decimals"   => @decimals
      }
    end

    # @private
    def inspect
      "#<RbMysql::Field:#{@name}>"
    end

    # @return [Boolean] true if numeric field.
    def is_num?
      @flags & NUM_FLAG != 0
    end

    # @return [Boolean] true if not null field.
    def is_not_null?
      @flags & NOT_NULL_FLAG != 0
    end

    # @return [Boolean] true if primary key field.
    def is_pri_key?
      @flags & PRI_KEY_FLAG != 0
    end

    # @return [Integer] maximum width of the field for the result set
    def max_length
      return @max_length if @max_length
      @max_length = 0
      @result.calculate_field_max_length if @result
      @max_length
    end

    attr_writer :max_length

    private

    def is_num_type?
      [TYPE_DECIMAL, TYPE_TINY, TYPE_SHORT, TYPE_LONG, TYPE_FLOAT, TYPE_DOUBLE, TYPE_LONGLONG, TYPE_INT24].include?(@type) || (@type == TYPE_TIMESTAMP && (@length == 14 || @length == 8))
    end

  end

  # @!visibility public
  # Result set
  class ResultBase
    include Enumerable

    # @return [Array<RbMysql::Field>] field list
    attr_reader :fields

    # @param [Array of RbMysql::Field] fields
    def initialize(fields)
      @fields = fields
      @field_index = 0             # index of field
      @records = []                # all records
      @index = 0                   # index of record
      @fieldname_with_table = nil
      @fetched_record = nil
    end

    # ignore
    # @return [void]
    def free
    end

    # @return [Integer] number of record
    def size
      @records.size
    end
    alias num_rows size

    # @return [Array] current record data
    def fetch
      @fetched_record = nil
      return nil if @index >= @records.size
      @records[@index] = @records[@index].to_a unless @records[@index].is_a? Array
      @fetched_record = @records[@index]
      @index += 1
      return @fetched_record
    end
    alias fetch_row fetch

    # Return data of current record as Hash.
    # The hash key is field name.
    # @param [Boolean] with_table if true, hash key is "table_name.field_name".
    # @return [Hash] current record data
    def fetch_hash(with_table=nil)
      row = fetch
      return nil unless row
      if with_table and @fieldname_with_table.nil?
        @fieldname_with_table = @fields.map{|f| [f.table, f.name].join(".")}
      end
      ret = {}
      @fields.each_index do |i|
        fname = with_table ? @fieldname_with_table[i] : @fields[i].name
        ret[fname] = row[i]
      end
      ret
    end

    # Iterate block with record.
    # @yield [Array] record data
    # @return [self] self. If block is not specified, this returns Enumerator.
    def each(&block)
      return enum_for(:each) unless block
      while rec = fetch
        block.call rec
      end
      self
    end

    # Iterate block with record as Hash.
    # @param [Boolean] with_table if true, hash key is "table_name.field_name".
    # @yield [Hash] record data
    # @return [self] self. If block is not specified, this returns Enumerator.
    def each_hash(with_table=nil, &block)
      return enum_for(:each_hash, with_table) unless block
      while rec = fetch_hash(with_table)
        block.call rec
      end
      self
    end

    # Set record position
    # @param [Integer] n record index
    # @return [self] self
    def data_seek(n)
      @index = n
      self
    end

    # @return [Integer] current record position
    def row_tell
      @index
    end

    # Set current position of record
    # @param [Integer] n record index
    # @return [Integer] previous position
    def row_seek(n)
      ret = @index
      @index = n
      ret
    end
  end

  # @!visibility public
  # Result set for simple query
  class Result < ResultBase
    # @private
    # @param [Array<RbMysql::Field>] fields
    # @param [RbMysql::Protocol] protocol
    def initialize(fields, protocol=nil)
      super fields
      return unless protocol
      @records = protocol.retr_all_records fields
      fields.each{|f| f.result = self}  # for calculating max_field
    end

    # @private
    # calculate max_length of all fields
    def calculate_field_max_length
      max_length = Array.new(@fields.size, 0)
      @records.each_with_index do |rec, i|
        rec = @records[i] = rec.to_a if rec.is_a? RawRecord
        max_length.each_index do |j|
          max_length[j] = rec[j].length if rec[j] && rec[j].length > max_length[j]
        end
      end
      max_length.each_with_index do |len, i|
        @fields[i].max_length = len
      end
    end

    # @return [RbMysql::Field] current field
    def fetch_field
      return nil if @field_index >= @fields.length
      ret = @fields[@field_index]
      @field_index += 1
      ret
    end

    # @return [Integer] current field position
    def field_tell
      @field_index
    end

    # Set field position
    # @param [Integer] n field index
    # @return [Integer] previous position
    def field_seek(n)
      ret = @field_index
      @field_index = n
      ret
    end

    # Return specified field
    # @param [Integer] n field index
    # @return [RbMysql::Field] field
    def fetch_field_direct(n)
      raise ClientError, "invalid argument: #{n}" if n < 0 or n >= @fields.length
      @fields[n]
    end

    # @return [Array<RbMysql::Field>] all fields
    def fetch_fields
      @fields
    end

    # @return [Array<Integer>] length of each fields
    def fetch_lengths
      return nil unless @fetched_record
      @fetched_record.map{|c|c.nil? ? 0 : c.length}
    end

    # @return [Integer] number of fields
    def num_fields
      @fields.size
    end
  end

  # @!visibility private
  # Result set for prepared statement
  class StatementResult < ResultBase
    # @private
    # @param [Array<RbMysql::Field>] fields
    # @param [RbMysql::Protocol] protocol
    # @param [RbMysql::Charset] charset
    def initialize(fields, protocol, charset)
      super fields
      @records = protocol.stmt_retr_all_records @fields, charset
    end
  end

  # @!visibility public
  # Prepared statement
  # @!attribute [r] affected_rows
  #   @return [Integer]
  # @!attribute [r] insert_id
  #   @return [Integer]
  # @!attribute [r] server_status
  #   @return [Integer]
  # @!attribute [r] warning_count
  #   @return [Integer]
  # @!attribute [r] param_count
  #   @return [Integer]
  # @!attribute [r] fields
  #   @return [Array<RbMysql::Field>]
  # @!attribute [r] sqlstate
  #   @return [String]
  class Stmt
    include Enumerable

    attr_reader :affected_rows, :insert_id, :server_status, :warning_count
    attr_reader :param_count, :fields, :sqlstate

    # @private
    def self.finalizer(protocol, statement_id)
      proc do
        protocol.gc_stmt statement_id
      end
    end

    # @private
    # @param [RbMysql::Protocol] protocol
    # @param [RbMysql::Charset] charset
    def initialize(protocol, charset)
      @protocol = protocol
      @charset = charset
      @statement_id = nil
      @affected_rows = @insert_id = @server_status = @warning_count = 0
      @sqlstate = "00000"
      @param_count = nil
      @bind_result = nil
    end

    # @private
    # parse prepared-statement and return {RbMysql::Stmt} object
    # @param [String] str query string
    # @return self
    def prepare(str)
      close
      begin
        @sqlstate = "00000"
        @statement_id, @param_count, @fields = @protocol.stmt_prepare_command(str)
      rescue ServerError => e
        @last_error = e
        @sqlstate = e.sqlstate
        raise
      end
      ObjectSpace.define_finalizer(self, self.class.finalizer(@protocol, @statement_id))
      self
    end

    # Execute prepared statement.
    # @param [Object] values values passed to query
    # @return [RbMysql::Stmt] self
    def execute(*values)
      raise ClientError, "not prepared" unless @param_count
      raise ClientError, "parameter count mismatch" if values.length != @param_count
      values = values.map{|v| @charset.convert v}
      begin
        @sqlstate = "00000"
        nfields = @protocol.stmt_execute_command @statement_id, values
        if nfields
          @fields = @protocol.retr_fields nfields
          @result = StatementResult.new @fields, @protocol, @charset
        else
          @affected_rows, @insert_id, @server_status, @warning_count, @info =
            @protocol.affected_rows, @protocol.insert_id, @protocol.server_status, @protocol.warning_count, @protocol.message
        end
        return self
      rescue ServerError => e
        @last_error = e
        @sqlstate = e.sqlstate
        raise
      end
    end

    # Close prepared statement
    # @return [void]
    def close
      ObjectSpace.undefine_finalizer(self)
      @protocol.stmt_close_command @statement_id if @statement_id
      @statement_id = nil
    end

    # @return [Array] current record data
    def fetch
      row = @result.fetch
      return row unless @bind_result
      row.zip(@bind_result).map do |col, type|
        if col.nil?
          nil
        elsif [Numeric, Integer, Fixnum].include? type
          col.to_i
        elsif type == String
          col.to_s
        elsif type == Float && !col.is_a?(Float)
          col.to_i.to_f
        elsif type == RbMysql::Time && !col.is_a?(RbMysql::Time)
          if col.to_s =~ /\A\d+\z/
            i = col.to_s.to_i
            if i < 100000000
              y = i/10000
              m = i/100%100
              d = i%100
              h, mm, s = 0
            else
              y = i/10000000000
              m = i/100000000%100
              d = i/1000000%100
              h = i/10000%100
              mm= i/100%100
              s = i%100
            end
            if y < 70
              y += 2000
            elsif y < 100
              y += 1900
            end
            RbMysql::Time.new(y, m, d, h, mm, s)
          else
            RbMysql::Time.new
          end
        else
          col
        end
      end
    end

    # Return data of current record as Hash.
    # The hash key is field name.
    # @param [Boolean] with_table if true, hash key is "table_name.field_name".
    # @return [Hash] record data
    def fetch_hash(with_table=nil)
      @result.fetch_hash with_table
    end

    # Set retrieve type of value
    # @param [Numeric / Fixnum / Integer / Float / String / RbMysql::Time / nil] args value type
    # @return [RbMysql::Stmt] self
    def bind_result(*args)
      if @fields.length != args.length
        raise ClientError, "bind_result: result value count(#{@fields.length}) != number of argument(#{args.length})"
      end
      args.each do |a|
        raise TypeError unless [Numeric, Fixnum, Integer, Float, String, RbMysql::Time, nil].include? a
      end
      @bind_result = args
      self
    end

    # Iterate block with record.
    # @yield [Array] record data
    # @return [RbMysql::Stmt] self
    # @return [Enumerator] If block is not specified
    def each(&block)
      return enum_for(:each) unless block
      while rec = fetch
        block.call rec
      end
      self
    end

    # Iterate block with record as Hash.
    # @param [Boolean] with_table if true, hash key is "table_name.field_name".
    # @yield [Hash] record data
    # @return [RbMysql::Stmt] self
    # @return [Enumerator] If block is not specified
    def each_hash(with_table=nil, &block)
      return enum_for(:each_hash, with_table) unless block
      while rec = fetch_hash(with_table)
        block.call rec
      end
      self
    end

    # @return [Integer] number of record
    def size
      @result.size
    end
    alias num_rows size

    # Set record position
    # @param [Integer] n record index
    # @return [void]
    def data_seek(n)
      @result.data_seek(n)
    end

    # @return [Integer] current record position
    def row_tell
      @result.row_tell
    end

    # Set current position of record
    # @param [Integer] n record index
    # @return [Integer] previous position
    def row_seek(n)
      @result.row_seek(n)
    end

    # @return [Integer] number of columns for last query
    def field_count
      @fields.length
    end

    # ignore
    # @return [void]
    def free_result
    end

    # Returns RbMysql::Result object that is empty.
    # Use fetch_fields to get list of fields.
    # @return [RbMysql::Result]
    def result_metadata
      return nil if @fields.empty?
      Result.new @fields
    end
  end

  # @!visibility public
  # @!attribute [rw] year
  #   @return [Integer]
  # @!attribute [rw] month
  #   @return [Integer]
  # @!attribute [rw] day
  #   @return [Integer]
  # @!attribute [rw] hour
  #   @return [Integer]
  # @!attribute [rw] minute
  #   @return [Integer]
  # @!attribute [rw] second
  #   @return [Integer]
  # @!attribute [rw] neg
  #   @return [Boolean] negative flag
  # @!attribute [rw] second_part
  #   @return [Integer]
  class Time
    # @param [Integer] year
    # @param [Integer] month
    # @param [Integer] day
    # @param [Integer] hour
    # @param [Integer] minute
    # @param [Integer] second
    # @param [Boolean] neg negative flag
    # @param [Integer] second_part
    def initialize(year=0, month=0, day=0, hour=0, minute=0, second=0, neg=false, second_part=0)
      @date_flag = !(hour && minute && second)
      @year, @month, @day, @hour, @minute, @second, @neg, @second_part =
        year.to_i, month.to_i, day.to_i, hour.to_i, minute.to_i, second.to_i, neg, second_part.to_i
    end
    attr_accessor :year, :month, :day, :hour, :minute, :second, :neg, :second_part
    alias mon month
    alias min minute
    alias sec second

    # @private
    def ==(other)
      other.is_a?(RbMysql::Time) &&
        @year == other.year && @month == other.month && @day == other.day &&
        @hour == other.hour && @minute == other.minute && @second == other.second &&
        @neg == neg && @second_part == other.second_part
    end

    # @private
    def eql?(other)
      self == other
    end

    # @return [String] "yyyy-mm-dd HH:MM:SS"
    def to_s
      if @date_flag
        sprintf "%04d-%02d-%02d", year, mon, day
      elsif year == 0 and mon == 0 and day == 0
        h = neg ? hour * -1 : hour
        sprintf "%02d:%02d:%02d", h, min, sec
      else
        sprintf "%04d-%02d-%02d %02d:%02d:%02d", year, mon, day, hour, min, sec
      end
    end

    # @return [Integer] yyyymmddHHMMSS
    def to_i
      sprintf("%04d%02d%02d%02d%02d%02d", year, mon, day, hour, min, sec).to_i
    end

    # @private
    def inspect
      sprintf "#<#{self.class.name}:%04d-%02d-%02d %02d:%02d:%02d>", year, mon, day, hour, min, sec
    end

  end

end