# -*- coding: binary -*-
# Copyright (C) 2008-2009 TOMITA Masahiro
# mailto:tommy@tmtm.org

require "enumerator"
require "uri"

# MySQL connection class.
# === Example
#  Mysql.connect("mysql://user:password@hostname:port/dbname") do |my|
#    res = my.query "select col1,col2 from tbl where id=?", 123
#    res.each do |c1, c2|
#      p c1, c2
#    end
#  end
class RbMysql

  dir = File.dirname __FILE__
  require "#{dir}/rbmysql/constants"
  require "#{dir}/rbmysql/error"
  require "#{dir}/rbmysql/charset"
  require "#{dir}/rbmysql/protocol"

  VERSION            = 30001               # Version number of this library
  MYSQL_UNIX_PORT    = "/tmp/mysql.sock"   # UNIX domain socket filename
  MYSQL_TCP_PORT     = 3306                # TCP socket port number

  OPTIONS = {
    :connect_timeout         => Integer,
#    :compress                => x,
#    :named_pipe              => x,
    :init_command            => String,
#    :read_default_file       => x,
#    :read_default_group      => x,
    :charset                 => Object,
#    :local_infile            => x,
#    :shared_memory_base_name => x,
    :read_timeout            => Integer,
    :write_timeout           => Integer,
#    :use_result              => x,
#    :use_remote_connection   => x,
#    :use_embedded_connection => x,
#    :guess_connection        => x,
#    :client_ip               => x,
#    :secure_auth             => x,
#    :report_data_truncation  => x,
#    :reconnect               => x,
#    :ssl_verify_server_cert  => x,
  }  # :nodoc:

  OPT2FLAG = {
#    :compress                => CLIENT_COMPRESS,
    :found_rows              => CLIENT_FOUND_ROWS,
    :ignore_sigpipe          => CLIENT_IGNORE_SIGPIPE,
    :ignore_space            => CLIENT_IGNORE_SPACE,
    :interactive             => CLIENT_INTERACTIVE,
    :local_files             => CLIENT_LOCAL_FILES,
#    :multi_results           => CLIENT_MULTI_RESULTS,
#    :multi_statements        => CLIENT_MULTI_STATEMENTS,
    :no_schema               => CLIENT_NO_SCHEMA,
#    :ssl                     => CLIENT_SSL,
  }  # :nodoc:

  attr_reader :charset               # character set of MySQL connection
  attr_reader :affected_rows         # number of affected records by insert/update/delete.
  attr_reader :insert_id             # latest auto_increment value.
  attr_reader :server_status         # :nodoc:
  attr_reader :warning_count         #
  attr_reader :server_version        #
  attr_reader :protocol              #
  attr_reader :sqlstate

  def self.new(*args, &block)  # :nodoc:
    my = self.allocate
    my.instance_eval{initialize(*args)}
    return my unless block
    begin
      return block.call(my)
    ensure
      my.close
    end
  end

  # === Return
  # The value that block returns if block is specified.
  # Otherwise this returns Mysql object.
  def self.connect(*args, &block)
    my = self.new(*args)
    my.connect
    return my unless block
    begin
      return block.call(my)
    ensure
      my.close
    end
  end

  # :call-seq:
  # new(conninfo, opt={})
  # new(conninfo, opt={}) {|my| ...}
  #
  # Connect to mysqld.
  # If block is specified then the connection is closed when exiting the block.
  # === Argument
  # conninfo ::
  #   [String / URI / Hash] Connection information.
  #   If conninfo is String then it's format must be "mysql://user:password@hostname:port/dbname".
  #   If conninfo is URI then it's scheme must be "mysql".
  #   If conninfo is Hash then valid keys are :host, :user, :password, :db, :port, :socket and :flag.
  # opt :: [Hash] options.
  # === Options
  # :connect_timeout :: [Numeric] The number of seconds before connection timeout.
  # :init_command    :: [String] Statement to execute when connecting to the MySQL server.
  # :charset         :: [String / Mysql::Charset] The character set to use as the default character set.
  # :read_timeout    :: [The timeout in seconds for attempts to read from the server.
  # :write_timeout   :: [Numeric] The timeout in seconds for attempts to write to the server.
  # :found_rows      :: [Boolean] Return the number of found (matched) rows, not the number of changed rows.
  # :ignore_space    :: [Boolean] Allow spaces after function names.
  # :interactive     :: [Boolean] Allow `interactive_timeout' seconds (instead of `wait_timeout' seconds) of inactivity before closing the connection.
  # :local_files     :: [Boolean] Enable `LOAD DATA LOCAL' handling.
  # :no_schema       :: [Boolean] Don't allow the DB_NAME.TBL_NAME.COL_NAME syntax.
  # === Block parameter
  # my :: [ Mysql ]
  def initialize(*args)
    @fields = nil
    @protocol = nil
    @charset = nil
    @connect_timeout = nil
    @read_timeout = nil
    @write_timeout = nil
    @init_command = nil
    @affected_rows = nil
    @server_version = nil
    @sqlstate = "00000"
    @param, opt = conninfo(*args)
    @connected = false
    set_option opt
  end

  # :call-seq:
  # connect(conninfo, opt={})
  #
  # connect to mysql server.
  # arguments are same as new().
  def connect(*args)
    param, opt = conninfo(*args)
    set_option opt
    param = @param.merge param
    @protocol = Protocol.new param[:host], param[:port], param[:socket], @connect_timeout, @read_timeout, @write_timeout
    @protocol.synchronize do
      init_packet = @protocol.read_initial_packet
      @server_version = init_packet.server_version.split(/\D/)[0,3].inject{|a,b|a.to_i*100+b.to_i}
      client_flags = CLIENT_LONG_PASSWORD | CLIENT_LONG_FLAG | CLIENT_TRANSACTIONS | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION
      client_flags |= CLIENT_CONNECT_WITH_DB if param[:db]
      client_flags |= param[:flag] if param[:flag]
      unless @charset
        @charset = Charset.by_number(init_packet.server_charset)
        @charset.encoding       # raise error if unsupported charset
      end
      netpw = init_packet.crypt_password param[:password]
      auth_packet = Protocol::AuthenticationPacket.new client_flags, 1024**3, @charset.number, param[:user], netpw, param[:db]
      @protocol.send_packet auth_packet
      @protocol.read            # skip OK packet
    end
    simple_query @init_command if @init_command
    return self
  end

  # disconnect from mysql.
  def close
    if @protocol
      @protocol.synchronize do
        @protocol.reset
        @protocol.send_packet Protocol::QuitPacket.new
        @protocol.close
        @protocol = nil
      end
    end
    return self
  end

  # set characterset of MySQL connection
  # === Argument
  # cs :: [String / Mysql::Charset]
  # === Return
  # cs
  def charset=(cs)
    charset = cs.is_a?(Charset) ? cs : Charset.by_name(cs)
    query "SET NAMES #{charset.name}" if @protocol
    @charset = charset
    cs
  end

  # Execute query string.
  # If params is specified, then the query is executed as prepared-statement automatically.
  # === Argument
  # str :: [String] Query.
  # params :: Parameters corresponding to place holder (`?') in str.
  # block :: If it is given then it is evaluated with Result object as argument.
  # === Return
  # Mysql::Result :: If result set exist.
  # nil :: If the query does not return result set.
  # self :: If block is specified.
  # === Block parameter
  # [ Mysql::Result ]
  # === Example
  #  my.query("select 1,NULL,'abc'").fetch  # => [1, nil, "abc"]
  def query(str, *params, &block)
    if params.empty?
      res = simple_query(str, &block)
    else
      res = prepare_query(str, *params, &block)
    end
    if res && block
      yield res
      return self
    end
    return res
  end

  def simple_query(str)  # :nodoc:
    @affected_rows = @insert_id = @server_status = @warning_count = 0
    @protocol.synchronize do
      begin
        @protocol.reset
        @protocol.send_packet Protocol::QueryPacket.new(@charset.convert(str))
        res_packet = @protocol.read_result_packet
        if res_packet.field_count == 0
          @affected_rows, @insert_id, @server_status, @warning_conut =
            res_packet.affected_rows, res_packet.insert_id, res_packet.server_status, res_packet.warning_count
          return nil
        else
          @fields = Array.new(res_packet.field_count).map{Field.new @protocol.read_field_packet}
          @protocol.read_eof_packet
          return SimpleQueryResult.new(self, @fields)
        end
      rescue ServerError => e
        @sqlstate = e.sqlstate
        raise
      end
    end
  end

  def prepare_query(str, *params)  # :nodoc:
    st = prepare(str)
    res = st.execute(*params)
    if st.fields.empty?
      @affected_rows = st.affected_rows
      @insert_id = st.insert_id
      @server_status = st.server_status
      @warning_count = st.warning_count
    end
    st.close
    return res
  end

  # Parse prepared-statement.
  # If block is specified then prepared-statement is closed when exiting the block.
  # === Argument
  # str   :: [String] query string
  # block :: If it is given then it is evaluated with Mysql::Statement object as argument.
  # === Return
  # Mysql::Statement :: Prepared-statement object
  # The block value if block is given.
  def prepare(str, &block)
    st = Statement.new self
    st.prepare str
    if block
      begin
        return block.call(st)
      ensure
        st.close
      end
    end
    return st
  end

  # Escape special character in MySQL.
  # === Note
  # In Ruby 1.8, this is not safe for multibyte charset such as 'SJIS'.
  # You should use place-holder in prepared-statement.
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

  # :call-seq:
  # statement()
  # statement() {|st| ... }
  #
  # Make empty prepared-statement object.
  # If block is specified then prepared-statement is closed when exiting the block.
  # === Block parameter
  # st :: [ Mysql::Stmt ] Prepared-statement object.
  # === Return
  # Mysql::Statement :: If block is not specified.
  # The value returned by block :: If block is specified.
  def statement(&block)
    st = Statement.new self
    if block
      begin
        return block.call(st)
      ensure
        st.close
      end
    end
    return st
  end

  # Get field(column) list
  # === Argument
  # table :: [String] table name.
  # === Return
  # Array of Mysql::Field
  def list_fields(table)
    @protocol.synchronize do
      begin
        @protocol.reset
        @protocol.send_packet Protocol::FieldListPacket.new(table)
        fields = []
        until Protocol.eof_packet?(data = @protocol.read)
          fields.push Field.new(Protocol::FieldPacket.parse(data))
        end
        return fields
      rescue ServerError => e
        @sqlstate = e.sqlstate
        raise
      end
    end
  end

  private

  # analyze argument and returns connection-parameter and option.
  #
  # connection-parameter's key :: :host, :user, :password, :db, :port, :socket, :flag
  # === Return
  # Hash :: connection parameters
  # Hash :: option {:optname => value, ...}
  def conninfo(*args)
    paramkeys = [:host, :user, :password, :db, :port, :socket, :flag]
    opt = {}
    if args.empty?
      param = {}
    elsif args.size == 1 and args.first.is_a? Hash
      arg = args.first.dup
      param = {}
      [:host, :user, :password, :db, :port, :socket, :flag].each do |k|
        param[k] = arg.delete k if arg.key? k
      end
      opt = arg
    else
      if args.last.is_a? Hash
        args = args.dup
        opt = args.pop
      end
      if args.size > 1 || args.first.nil? || args.first.is_a?(String) && args.first !~ /\Amysql:/
        host, user, password, db, port, socket, flag = args
        param = {:host=>host, :user=>user, :password=>password, :db=>db, :port=>port, :socket=>socket, :flag=>flag}
      elsif args.first.is_a? Hash
        param = args.first.dup
        param.keys.each do |k|
          unless paramkeys.include? k
            raise ArgumentError, "Unknown parameter: #{k.inspect}"
          end
        end
      else
        if args.first =~ /\Amysql:/
          uri = URI.parse args.first
        elsif args.first.is_a? URI
          uri = args.first
        else
          raise ArgumentError, "Invalid argument: #{args.first.inspect}"
        end
        unless uri.scheme == "mysql"
          raise ArgumentError, "Invalid scheme: #{uri.scheme}"
        end
        param = {:host=>uri.host, :user=>uri.user, :password=>uri.password, :port=>uri.port||MYSQL_TCP_PORT}
        param[:db] = uri.path.split(/\/+/).reject{|a|a.empty?}.first
        if uri.query
          uri.query.split(/\&/).each do |a|
            k, v = a.split(/\=/, 2)
            if k == "socket"
              param[:socket] = v
            elsif k == "flag"
              param[:flag] = v.to_i
            else
              opt[k.intern] = v
            end
          end
        end
      end
    end
    param[:flag] = 0 unless param.key? :flag
    opt.keys.each do |k|
      if OPT2FLAG.key? k and opt[k]
        param[:flag] |= OPT2FLAG[k]
        next
      end
      unless OPTIONS.key? k
        raise ArgumentError, "Unknown option: #{k.inspect}"
      end
      opt[k] = opt[k].to_i if OPTIONS[k] == Integer
    end
    return param, opt
  end

  def set_option(opt)
    opt.each do |k,v|
      raise ClientError, "unknown option: #{k.inspect}" unless OPTIONS.key? k
      type = OPTIONS[k]
      if type.is_a? Class
        raise ClientError, "invalid value for #{k.inspect}: #{v.inspect}" unless v.is_a? type
      end
    end

    charset = opt[:charset] if opt.key? :charset
    @connect_timeout = opt[:connect_timeout] || @connect_timeout
    @init_command = opt[:init_command] || @init_command
    @read_timeout = opt[:read_timeout] || @read_timeout
    @write_timeout = opt[:write_timeout] || @write_timeout
  end

  # Field class
  class Field
    attr_reader :db, :table, :org_table, :name, :org_name, :charsetnr, :length, :type, :flags, :decimals, :default
    alias :def :default

    # === Argument
    # packet :: [Protocol::FieldPacket]
    def initialize(packet)
      @db, @table, @org_table, @name, @org_name, @charsetnr, @length, @type, @flags, @decimals, @default =
        packet.db, packet.table, packet.org_table, packet.name, packet.org_name, packet.charsetnr, packet.length, packet.type, packet.flags, packet.decimals, packet.default
      @flags |= NUM_FLAG if is_num_type?
    end

    # Return true if numeric field.
    def is_num?
      @flags & NUM_FLAG != 0
    end

    # Return true if not null field.
    def is_not_null?
      @flags & NOT_NULL_FLAG != 0
    end

    # Return true if primary key field.
    def is_pri_key?
      @flags & PRI_KEY_FLAG != 0
    end

    private

    def is_num_type?
      [TYPE_DECIMAL, TYPE_TINY, TYPE_SHORT, TYPE_LONG, TYPE_FLOAT, TYPE_DOUBLE, TYPE_LONGLONG, TYPE_INT24].include?(@type) || (@type == TYPE_TIMESTAMP && (@length == 14 || @length == 8))
    end

  end

  # Result set
  class Result
    include Enumerable

    attr_reader :fields

    def initialize(mysql, fields)
      @fields = fields
      @fieldname_with_table = nil
      @index = 0
      @records = recv_all_records mysql.protocol, fields, mysql.charset
    end

    def size
      @records.size
    end

    def fetch_row
      return nil if @index >= @records.size
      rec = @records[@index]
      @index += 1
      return rec
    end

    alias fetch fetch_row

    def fetch_hash(with_table=nil)
      row = fetch_row
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

    def each(&block)
      return enum_for(:each) unless block
      while rec = fetch_row
        block.call rec
      end
      self
    end

    def each_hash(with_table=nil, &block)
      return enum_for(:each_hash, with_table) unless block
      while rec = fetch_hash(with_table)
        block.call rec
      end
      self
    end
  end

  # Result set for simple query
  class SimpleQueryResult < Result

    private

    def recv_all_records(protocol, fields, charset)
      ret = []
      while true
        data = protocol.read
        break if Protocol.eof_packet? data
        rec = fields.map do |f|
          v = Protocol.lcs2str! data
          convert_str_to_ruby_value f, v, charset
        end
        ret.push rec
      end
      ret
    end

    MYSQL_RUBY_TYPE = {
      Field::TYPE_BIT         => :binary,
      Field::TYPE_DECIMAL     => :string,
      Field::TYPE_VARCHAR     => :string,
      Field::TYPE_NEWDECIMAL  => :string,
      Field::TYPE_TINY_BLOB   => :string,
      Field::TYPE_MEDIUM_BLOB => :string,
      Field::TYPE_LONG_BLOB   => :string,
      Field::TYPE_BLOB        => :string,
      Field::TYPE_VAR_STRING  => :string,
      Field::TYPE_STRING      => :string,
      Field::TYPE_TINY        => :integer,
      Field::TYPE_SHORT       => :integer,
      Field::TYPE_LONG        => :integer,
      Field::TYPE_LONGLONG    => :integer,
      Field::TYPE_INT24       => :integer,
      Field::TYPE_YEAR        => :integer,
      Field::TYPE_FLOAT       => :float,
      Field::TYPE_DOUBLE      => :float,
      Field::TYPE_TIMESTAMP   => :datetime,
      Field::TYPE_DATE        => :datetime,
      Field::TYPE_DATETIME    => :datetime,
      Field::TYPE_NEWDATE     => :datetime,
      Field::TYPE_TIME        => :time,
    }

    def convert_str_to_ruby_value(field, value, charset)
      return nil if value.nil?
      case MYSQL_RUBY_TYPE[field.type]
      when :binary
        Charset.to_binary(value)
      when :string
        field.flags & Field::BINARY_FLAG == 0 ? charset.force_encoding(value) : Charset.to_binary(value)
      when :integer
        value.to_i
      when :float
        value.to_f
      when :datetime
        unless value =~ /\A(\d\d\d\d).(\d\d).(\d\d)(?:.(\d\d).(\d\d).(\d\d))?\z/
          raise "unsupported format date type: #{value}"
        end
        Time.new($1, $2, $3, $4, $5, $6)
      when :time
        unless value =~ /\A(-?)(\d+).(\d\d).(\d\d)?\z/
          raise "unsupported format time type: #{value}"
        end
        Time.new(0, 0, 0, $2, $3, $4, $1=="-")
      else
        raise "unknown mysql type: #{field.type}"
      end
    end
  end

  # Result set for prepared statement
  class StatementResult < Result

    private

    def recv_all_records(protocol, fields, charset)
      ret = []
      while rec = parse_data(protocol.read, fields, charset)
        ret.push rec
      end
      ret
    end

    def parse_data(data, fields, charset)
      return nil if Protocol.eof_packet? data
      data.slice!(0)  # skip first byte
      null_bit_map = data.slice!(0, (fields.length+7+2)/8).unpack("b*").first
      ret = fields.each_with_index.map do |f, i|
        if null_bit_map[i+2] == ?1
          nil
        else
          unsigned = f.flags & Field::UNSIGNED_FLAG != 0
          v = Protocol.net2value(data, f.type, unsigned)
          if v.is_a? Numeric or v.is_a? RbMysql::Time
            v
          elsif f.type == Field::TYPE_BIT or f.flags & Field::BINARY_FLAG != 0
            Charset.to_binary(v)
          else
            charset.force_encoding(v)
          end
        end
      end
      ret
    end
  end

  # Prepared statement
  class Statement
    attr_reader :affected_rows, :insert_id, :server_status, :warning_count
    attr_reader :param_count, :fields, :sqlstate

    def self.finalizer(protocol, statement_id)
      proc do
        Thread.new do
          protocol.synchronize do
            protocol.reset
            protocol.send_packet Protocol::StmtClosePacket.new(statement_id)
          end
        end
      end
    end

    def initialize(mysql)
      @mysql = mysql
      @protocol = mysql.protocol
      @statement_id = nil
      @affected_rows = @insert_id = @server_status = @warning_count = 0
      @sqlstate = "00000"
      @param_count = nil
    end

    # parse prepared-statement and return Mysql::Statement object
    # === Argument
    # str :: [String] query string
    # === Return
    # self
    def prepare(str)
      close
      @protocol.synchronize do
        begin
          @sqlstate = "00000"
          @protocol.reset
          @protocol.send_packet Protocol::PreparePacket.new(@mysql.charset.convert(str))
          res_packet = @protocol.read_prepare_result_packet
          if res_packet.param_count > 0
            res_packet.param_count.times{@protocol.read}   # skip parameter packet
            @protocol.read_eof_packet
          end
          if res_packet.field_count > 0
            fields = Array.new(res_packet.field_count).map{Field.new @protocol.read_field_packet}
            @protocol.read_eof_packet
          else
            fields = []
          end
          @statement_id = res_packet.statement_id
          @param_count = res_packet.param_count
          @fields = fields
        rescue ServerError => e
          @sqlstate = e.sqlstate
          raise
        end
      end
      ObjectSpace.define_finalizer(self, self.class.finalizer(@protocol, @statement_id))
      self
    end

    # execute prepared-statement.
    # === Return
    # Mysql::Result
    def execute(*values)
      raise ClientError, "not prepared" unless @param_count
      raise ClientError, "parameter count mismatch" if values.length != @param_count
      values = values.map{|v| @mysql.charset.convert v}
      @protocol.synchronize do
        begin
          @sqlstate = "00000"
          @protocol.reset
          @protocol.send_packet Protocol::ExecutePacket.new(@statement_id, CURSOR_TYPE_NO_CURSOR, values)
          res_packet = @protocol.read_result_packet
          raise ProtocolError, "invalid field_count" unless res_packet.field_count == @fields.length
          @fieldname_with_table = nil
          if res_packet.field_count == 0
            @affected_rows, @insert_id, @server_status, @warning_conut =
              res_packet.affected_rows, res_packet.insert_id, res_packet.server_status, res_packet.warning_count
            return nil
          end
          @fields = Array.new(res_packet.field_count).map{Field.new @protocol.read_field_packet}
          @protocol.read_eof_packet
          return StatementResult.new(@mysql, @fields)
        rescue ServerError => e
          @sqlstate = e.sqlstate
          raise
        end
      end
    end

    def close
      ObjectSpace.undefine_finalizer(self)
      @protocol.synchronize do
        @protocol.reset
        if @statement_id
          @protocol.send_packet Protocol::StmtClosePacket.new(@statement_id)
          @statement_id = nil
        end
      end
    end
  end

  class Time
    def initialize(year=0, month=0, day=0, hour=0, minute=0, second=0, neg=false, second_part=0)
      @year, @month, @day, @hour, @minute, @second, @neg, @second_part =
        year.to_i, month.to_i, day.to_i, hour.to_i, minute.to_i, second.to_i, neg, second_part.to_i
    end
    attr_accessor :year, :month, :day, :hour, :minute, :second, :neg, :second_part
    alias mon month
    alias min minute
    alias sec second

    def ==(other)
      other.is_a?(RbMysql::Time) &&
        @year == other.year && @month == other.month && @day == other.day &&
        @hour == other.hour && @minute == other.minute && @second == other.second &&
        @neg == neg && @second_part == other.second_part
    end

    def eql?(other)
      self == other
    end

    def to_s
      if year == 0 and mon == 0 and day == 0
        h = neg ? hour * -1 : hour
        sprintf "%02d:%02d:%02d", h, min, sec
      else
        sprintf "%04d-%02d-%02d %02d:%02d:%02d", year, mon, day, hour, min, sec
      end
    end

  end

end

