# coding: ascii-8bit
# Copyright (C) 2008-2012 TOMITA Masahiro
# mailto:tommy@tmtm.org

require "socket"
require "timeout"
require "digest/sha1"
require "stringio"

class RbMysql
  # MySQL network protocol
  class Protocol

    VERSION = 10
    MAX_PACKET_LENGTH = 2**24-1

    # Convert netdata to Ruby value
    # === Argument
    # data :: [Packet] packet data
    # type :: [Integer] field type
    # unsigned :: [true or false] true if value is unsigned
    # === Return
    # Object :: converted value.
    def self.net2value(pkt, type, unsigned)
      case type
      when Field::TYPE_STRING, Field::TYPE_VAR_STRING, Field::TYPE_NEWDECIMAL, Field::TYPE_BLOB, Field::TYPE_JSON
        return pkt.lcs
      when Field::TYPE_TINY
        v = pkt.utiny
        return unsigned ? v : v < 128 ? v : v-256
      when Field::TYPE_SHORT
        v = pkt.ushort
        return unsigned ? v : v < 32768 ? v : v-65536
      when Field::TYPE_INT24, Field::TYPE_LONG
        v = pkt.ulong
        return unsigned ? v : v < 0x8000_0000 ? v : v-0x10000_0000
      when Field::TYPE_LONGLONG
        n1, n2 = pkt.ulong, pkt.ulong
        v = (n2 << 32) | n1
        return unsigned ? v : v < 0x8000_0000_0000_0000 ? v : v-0x10000_0000_0000_0000
      when Field::TYPE_FLOAT
        return pkt.read(4).unpack('e').first
      when Field::TYPE_DOUBLE
        return pkt.read(8).unpack('E').first
      when Field::TYPE_DATE
        len = pkt.utiny
        y, m, d = pkt.read(len).unpack("vCC")
        t = RbMysql::Time.new(y, m, d, nil, nil, nil)
        return t
      when Field::TYPE_DATETIME, Field::TYPE_TIMESTAMP
        len = pkt.utiny
        y, m, d, h, mi, s, sp = pkt.read(len).unpack("vCCCCCV")
        return RbMysql::Time.new(y, m, d, h, mi, s, false, sp)
      when Field::TYPE_TIME
        len = pkt.utiny
        sign, d, h, mi, s, sp = pkt.read(len).unpack("CVCCCV")
        h = d.to_i * 24 + h.to_i
        return RbMysql::Time.new(0, 0, 0, h, mi, s, sign!=0, sp)
      when Field::TYPE_YEAR
        return pkt.ushort
      when Field::TYPE_BIT
        return pkt.lcs
      else
        raise "not implemented: type=#{type}"
      end
    end

    # convert Ruby value to netdata
    # === Argument
    # v :: [Object] Ruby value.
    # === Return
    # Integer :: type of column. Field::TYPE_*
    # String :: netdata
    # === Exception
    # ProtocolError :: value too large / value is not supported
    def self.value2net(v)
      case v
      when nil
        type = Field::TYPE_NULL
        val = ""
      when Integer
        if -0x8000_0000 <= v && v < 0x8000_0000
          type = Field::TYPE_LONG
          val = [v].pack('V')
        elsif -0x8000_0000_0000_0000 <= v && v < 0x8000_0000_0000_0000
          type = Field::TYPE_LONGLONG
          val = [v&0xffffffff, v>>32].pack("VV")
        elsif 0x8000_0000_0000_0000 <= v && v <= 0xffff_ffff_ffff_ffff
          type = Field::TYPE_LONGLONG | 0x8000
          val = [v&0xffffffff, v>>32].pack("VV")
        else
          raise ProtocolError, "value too large: #{v}"
        end
      when Float
        type = Field::TYPE_DOUBLE
        val = [v].pack("E")
      when String
        type = Field::TYPE_STRING
        val = Packet.lcs(v)
      when ::Time
        type = Field::TYPE_DATETIME
        val = [11, v.year, v.month, v.day, v.hour, v.min, v.sec, v.usec].pack("CvCCCCCV")
      when RbMysql::Time
        type = Field::TYPE_DATETIME
        val = [11, v.year, v.month, v.day, v.hour, v.min, v.sec, v.second_part].pack("CvCCCCCV")
      else
        raise ProtocolError, "class #{v.class} is not supported"
      end
      return type, val
    end

    attr_reader :server_info
    attr_reader :server_version
    attr_reader :thread_id
    attr_reader :sqlstate
    attr_reader :affected_rows
    attr_reader :insert_id
    attr_reader :server_status
    attr_reader :warning_count
    attr_reader :message
    attr_accessor :charset

    # @state variable keep state for connection.
    # :INIT   :: Initial state.
    # :READY  :: Ready for command.
    # :FIELD  :: After query(). retr_fields() is needed.
    # :RESULT :: After retr_fields(), retr_all_records() or stmt_retr_all_records() is needed.

    # make socket connection to server.
    # === Argument
    # host :: [String] if "localhost" or "" nil then use UNIXSocket. Otherwise use TCPSocket
    # port :: [Integer] port number using by TCPSocket
    # socket :: [String] socket file name using by UNIXSocket
    # conn_timeout :: [Integer] connect timeout (sec).
    # read_timeout :: [Integer] read timeout (sec).
    # write_timeout :: [Integer] write timeout (sec).
    # === Exception
    # [ClientError] :: connection timeout
    def initialize(host, port, socket, conn_timeout, read_timeout, write_timeout)
      @insert_id = 0
      @warning_count = 0
      @gc_stmt_queue = []   # stmt id list which GC destroy.
      set_state :INIT
      @read_timeout = read_timeout
      @write_timeout = write_timeout
      begin
        Timeout.timeout conn_timeout do
          if host.nil? or host.empty? or host == "localhost"
            socket ||= ENV["MYSQL_UNIX_PORT"] || MYSQL_UNIX_PORT
            @sock = UNIXSocket.new socket
          else
            port ||= ENV["MYSQL_TCP_PORT"] || (Socket.getservbyname("mysql","tcp") rescue MYSQL_TCP_PORT)
            @sock = TCPSocket.new host, port
          end
        end
      rescue Timeout::Error
        raise ClientError, "connection timeout"
      end
    end

    def close
      @sock.close
    end

    # initial negotiate and authenticate.
    # === Argument
    # user    :: [String / nil] username
    # passwd  :: [String / nil] password
    # db      :: [String / nil] default database name. nil: no default.
    # flag    :: [Integer] client flag
    # charset :: [RbMysql::Charset / nil] charset for connection. nil: use server's charset
    # === Exception
    # ProtocolError :: The old style password is not supported
    def authenticate(user, passwd, db, flag, charset)
      check_state :INIT
      @authinfo = [user, passwd, db, flag, charset]
      reset
      init_packet = InitialPacket.parse read
      @server_info = init_packet.server_version
      @server_version = init_packet.server_version.split(/\D/)[0,3].inject{|a,b|a.to_i*100+b.to_i}
      @thread_id = init_packet.thread_id
      @client_flags = CLIENT_LONG_PASSWORD | CLIENT_LONG_FLAG | CLIENT_TRANSACTIONS | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION
      @client_flags |= CLIENT_CONNECT_WITH_DB if db
      @client_flags |= flag
      @charset = charset
      unless @charset
        @charset = Charset.by_number(init_packet.server_charset)
        @charset.encoding       # raise error if unsupported charset
      end
      netpw = encrypt_password passwd, init_packet.scramble_buff
      write AuthenticationPacket.serialize(@client_flags, 1024**3, @charset.number, user, netpw, db)
      raise ProtocolError, 'The old style password is not supported' if read.to_s == "\xfe"
      set_state :READY
    end

    # Quit command
    def quit_command
      synchronize do
        reset
        write [COM_QUIT].pack("C")
        close
      end
    end

    # Query command
    # === Argument
    # query :: [String] query string
    # === Return
    # [Integer / nil] number of fields of results. nil if no results.
    def query_command(query)
      check_state :READY
      begin
        reset
        write [COM_QUERY, @charset.convert(query)].pack("Ca*")
        get_result
      rescue
        set_state :READY
        raise
      end
    end

    # get result of query.
    # === Return
    # [integer / nil] number of fields of results. nil if no results.
    def get_result
      begin
        res_packet = ResultPacket.parse read
        if res_packet.field_count.to_i > 0  # result data exists
          set_state :FIELD
          return res_packet.field_count
        end
        if res_packet.field_count.nil?      # LOAD DATA LOCAL INFILE
          if @client_flags.to_i & CLIENT_LOCAL_FILES == 0
            raise ProtocolError, 'Load data local infile forbidden'
          end
          filename = res_packet.message
          File.open(filename){|f| write f}
          write nil  # EOF mark
          read
        end
        @affected_rows, @insert_id, @server_status, @warning_count, @message =
          res_packet.affected_rows, res_packet.insert_id, res_packet.server_status, res_packet.warning_count, res_packet.message
        set_state :READY
        return nil
      rescue
        set_state :READY
        raise
      end
    end

    # Retrieve n fields
    # === Argument
    # n :: [Integer] number of fields
    # === Return
    # [Array of RbMysql::Field] field list
    def retr_fields(n)
      check_state :FIELD
      begin
        fields = n.times.map{Field.new FieldPacket.parse(read)}
        read_eof_packet
        set_state :RESULT
        fields
      rescue
        set_state :READY
        raise
      end
    end

    # Retrieve all records for simple query
    # === Argument
    # fields :: [Array<RbMysql::Field>] number of fields
    # === Return
    # [Array of Array of String] all records
    def retr_all_records(fields)
      check_state :RESULT
      enc = charset.encoding
      begin
        all_recs = []
        until (pkt = read).eof?
          all_recs.push RawRecord.new(pkt, fields, enc)
        end
        pkt.read(3)
        @server_status = pkt.utiny
        all_recs
      ensure
        set_state :READY
      end
    end

    # Field list command
    # === Argument
    # table :: [String] table name.
    # field :: [String / nil] field name that may contain wild card.
    # === Return
    # [Array of Field] field list
    def field_list_command(table, field)
      synchronize do
        reset
        write [COM_FIELD_LIST, table, 0, field].pack("Ca*Ca*")
        fields = []
        until (data = read).eof?
          fields.push Field.new(FieldPacket.parse(data))
        end
        return fields
      end
    end

    # Process info command
    # === Return
    # [Array of Field] field list
    def process_info_command
      check_state :READY
      begin
        reset
        write [COM_PROCESS_INFO].pack("C")
        field_count = read.lcb
        fields = field_count.times.map{Field.new FieldPacket.parse(read)}
        read_eof_packet
        set_state :RESULT
        return fields
      rescue
        set_state :READY
        raise
      end
    end

    # Ping command
    def ping_command
      simple_command [COM_PING].pack("C")
    end

    # Kill command
    def kill_command(pid)
      simple_command [COM_PROCESS_KILL, pid].pack("CV")
    end

    # Refresh command
    def refresh_command(op)
      simple_command [COM_REFRESH, op].pack("CC")
    end

    # Set option command
    def set_option_command(opt)
      simple_command [COM_SET_OPTION, opt].pack("Cv")
    end

    # Shutdown command
    def shutdown_command(level)
      simple_command [COM_SHUTDOWN, level].pack("CC")
    end

    # Statistics command
    def statistics_command
      simple_command [COM_STATISTICS].pack("C")
    end

    # Stmt prepare command
    # === Argument
    # stmt :: [String] prepared statement
    # === Return
    # [Integer] statement id
    # [Integer] number of parameters
    # [Array of Field] field list
    def stmt_prepare_command(stmt)
      synchronize do
        reset
        write [COM_STMT_PREPARE, charset.convert(stmt)].pack("Ca*")
        res_packet = PrepareResultPacket.parse read
        if res_packet.param_count > 0
          res_packet.param_count.times{read}    # skip parameter packet
          read_eof_packet
        end
        if res_packet.field_count > 0
          fields = res_packet.field_count.times.map{Field.new FieldPacket.parse(read)}
          read_eof_packet
        else
          fields = []
        end
        return res_packet.statement_id, res_packet.param_count, fields
      end
    end

    # Stmt execute command
    # === Argument
    # stmt_id :: [Integer] statement id
    # values  :: [Array] parameters
    # === Return
    # [Integer] number of fields
    def stmt_execute_command(stmt_id, values)
      check_state :READY
      begin
        reset
        write ExecutePacket.serialize(stmt_id, RbMysql::Stmt::CURSOR_TYPE_NO_CURSOR, values)
        get_result
      rescue
        set_state :READY
        raise
      end
    end

    # Retrieve all records for prepared statement
    # === Argument
    # fields  :: [Array of RbMysql::Fields] field list
    # charset :: [RbMysql::Charset]
    # === Return
    # [Array of Array of Object] all records
    def stmt_retr_all_records(fields, charset)
      check_state :RESULT
      enc = charset.encoding
      begin
        all_recs = []
        until (pkt = read).eof?
          all_recs.push StmtRawRecord.new(pkt, fields, enc)
        end
        all_recs
      ensure
        set_state :READY
      end
    end

    # Stmt close command
    # === Argument
    # stmt_id :: [Integer] statement id
    def stmt_close_command(stmt_id)
      synchronize do
        reset
        write [COM_STMT_CLOSE, stmt_id].pack("CV")
      end
    end

    def gc_stmt(stmt_id)
      @gc_stmt_queue.push stmt_id
    end

    private

    def check_state(st)
      raise 'command out of sync' unless @state == st
    end

    def set_state(st)
      @state = st
      if st == :READY
        gc_disabled = GC.disable
        begin
          while st = @gc_stmt_queue.shift
            reset
            write [COM_STMT_CLOSE, st].pack("CV")
          end
        ensure
          GC.enable unless gc_disabled
        end
      end
    end

    def synchronize
      begin
        check_state :READY
        return yield
      ensure
        set_state :READY
      end
    end

    # Reset sequence number
    def reset
      @seq = 0    # packet counter. reset by each command
    end

    # Read one packet data
    # === Return
    # [Packet] packet data
    # === Exception
    # [ProtocolError] invalid packet sequence number
    def read
      data = ''
      len = nil
      begin
        Timeout.timeout @read_timeout do
          header = @sock.read(4)
          raise EOFError unless header && header.length == 4
          len1, len2, seq = header.unpack("CvC")
          len = (len2 << 8) + len1
          raise ProtocolError, "invalid packet: sequence number mismatch(#{seq} != #{@seq}(expected))" if @seq != seq
          @seq = (@seq + 1) % 256
          ret = @sock.read(len)
          raise EOFError unless ret && ret.length == len
          data.concat ret
        end
      rescue EOFError
        raise ClientError::ServerGoneError, 'MySQL server has gone away'
      rescue Timeout::Error
        raise ClientError, "read timeout"
      end while len == MAX_PACKET_LENGTH

      @sqlstate = "00000"

      # Error packet
      if data[0] == ?\xff
        f, errno, marker, @sqlstate, message = data.unpack("Cvaa5a*")
        unless marker == "#"
          f, errno, message = data.unpack("Cva*")    # Version 4.0 Error
          @sqlstate = ""
        end
        message.force_encoding(@charset.encoding)
        if RbMysql::ServerError::ERROR_MAP.key? errno
          raise RbMysql::ServerError::ERROR_MAP[errno].new(message, @sqlstate)
        end
        raise RbMysql::ServerError.new(message, @sqlstate)
      end
      Packet.new(data)
    end

    # Write one packet data
    # === Argument
    # data :: [String / IO] packet data. If data is nil, write empty packet.
    def write(data)
      begin
        @sock.sync = false
        if data.nil?
          Timeout.timeout @write_timeout do
            @sock.write [0, 0, @seq].pack("CvC")
          end
          @seq = (@seq + 1) % 256
        else
          data = StringIO.new data if data.is_a? String
          while d = data.read(MAX_PACKET_LENGTH)
            Timeout.timeout @write_timeout do
              @sock.write [d.length%256, d.length/256, @seq].pack("CvC")
              @sock.write d
            end
            @seq = (@seq + 1) % 256
          end
        end
        @sock.sync = true
        Timeout.timeout @write_timeout do
          @sock.flush
        end
      rescue Errno::EPIPE
        raise ClientError::ServerGoneError, 'MySQL server has gone away'
      rescue Timeout::Error
        raise ClientError, "write timeout"
      end
    end

    # Read EOF packet
    # === Exception
    # [ProtocolError] packet is not EOF
    def read_eof_packet
      raise ProtocolError, "packet is not EOF" unless read.eof?
    end

    # Send simple command
    # === Argument
    # packet :: [String] packet data
    # === Return
    # [String] received data
    def simple_command(packet)
      synchronize do
        reset
        write packet
        read.to_s
      end
    end

    # Encrypt password
    # === Argument
    # plain    :: [String] plain password.
    # scramble :: [String] scramble code from initial packet.
    # === Return
    # [String] encrypted password
    def encrypt_password(plain, scramble)
      return "" if plain.nil? or plain.empty?
      hash_stage1 = Digest::SHA1.digest plain
      hash_stage2 = Digest::SHA1.digest hash_stage1
      return hash_stage1.unpack("C*").zip(Digest::SHA1.digest(scramble+hash_stage2).unpack("C*")).map{|a,b| a^b}.pack("C*")
    end

    # Initial packet
    class InitialPacket
      def self.parse(pkt)
        protocol_version = pkt.utiny
        server_version = pkt.string
        thread_id = pkt.ulong
        scramble_buff = pkt.read(8)
        f0 = pkt.utiny
        server_capabilities = pkt.ushort
        server_charset = pkt.utiny
        server_status = pkt.ushort
        _f1 = pkt.read(13)
        rest_scramble_buff = pkt.string
        raise ProtocolError, "unsupported version: #{protocol_version}" unless protocol_version == VERSION
        raise ProtocolError, "invalid packet: f0=#{f0}" unless f0 == 0
        scramble_buff.concat rest_scramble_buff
        self.new protocol_version, server_version, thread_id, server_capabilities, server_charset, server_status, scramble_buff
      end

      attr_reader :protocol_version, :server_version, :thread_id, :server_capabilities, :server_charset, :server_status, :scramble_buff

      def initialize(*args)
        @protocol_version, @server_version, @thread_id, @server_capabilities, @server_charset, @server_status, @scramble_buff = args
      end
    end

    # Result packet
    class ResultPacket
      def self.parse(pkt)
        field_count = pkt.lcb
        if field_count == 0
          affected_rows = pkt.lcb
          insert_id = pkt.lcb
          server_status = pkt.ushort
          warning_count = pkt.ushort
          message = pkt.lcs
          return self.new(field_count, affected_rows, insert_id, server_status, warning_count, message)
        elsif field_count.nil?   # LOAD DATA LOCAL INFILE
          return self.new(nil, nil, nil, nil, nil, pkt.to_s)
        else
          return self.new(field_count)
        end
      end

      attr_reader :field_count, :affected_rows, :insert_id, :server_status, :warning_count, :message

      def initialize(*args)
        @field_count, @affected_rows, @insert_id, @server_status, @warning_count, @message = args
      end
    end

    # Field packet
    class FieldPacket
      def self.parse(pkt)
        _first = pkt.lcs
        db = pkt.lcs
        table = pkt.lcs
        org_table = pkt.lcs
        name = pkt.lcs
        org_name = pkt.lcs
        _f0 = pkt.utiny
        charsetnr = pkt.ushort
        length = pkt.ulong
        type = pkt.utiny
        flags = pkt.ushort
        decimals = pkt.utiny
        f1 = pkt.ushort

        raise ProtocolError, "invalid packet: f1=#{f1}" unless f1 == 0
        default = pkt.lcs
        return self.new(db, table, org_table, name, org_name, charsetnr, length, type, flags, decimals, default)
      end

      attr_reader :db, :table, :org_table, :name, :org_name, :charsetnr, :length, :type, :flags, :decimals, :default

      def initialize(*args)
        @db, @table, @org_table, @name, @org_name, @charsetnr, @length, @type, @flags, @decimals, @default = args
      end
    end

    # Prepare result packet
    class PrepareResultPacket
      def self.parse(pkt)
        raise ProtocolError, "invalid packet" unless pkt.utiny == 0
        statement_id = pkt.ulong
        field_count = pkt.ushort
        param_count = pkt.ushort
        f = pkt.utiny
        warning_count = pkt.ushort
        raise ProtocolError, "invalid packet" unless f == 0x00
        self.new statement_id, field_count, param_count, warning_count
      end

      attr_reader :statement_id, :field_count, :param_count, :warning_count

      def initialize(*args)
        @statement_id, @field_count, @param_count, @warning_count = args
      end
    end

    # Authentication packet
    class AuthenticationPacket
      def self.serialize(client_flags, max_packet_size, charset_number, username, scrambled_password, databasename)
        [
          client_flags,
          max_packet_size,
          Packet.lcb(charset_number),
          "",                   # always 0x00 * 23
          username,
          Packet.lcs(scrambled_password),
          databasename
        ].pack("VVa*a23Z*A*Z*")
      end
    end

    # Execute packet
    class ExecutePacket
      def self.serialize(statement_id, cursor_type, values)
        nbm = null_bitmap values
        netvalues = ""
        types = values.map do |v|
          t, n = Protocol.value2net v
          netvalues.concat n if v
          t
        end
        [RbMysql::COM_STMT_EXECUTE, statement_id, cursor_type, 1, nbm, 1, types.pack("v*"), netvalues].pack("CVCVa*Ca*a*")
      end

      # make null bitmap
      #
      # If values is [1, nil, 2, 3, nil] then returns "\x12"(0b10010).
      def self.null_bitmap(values)
        bitmap = values.enum_for(:each_slice,8).map do |vals|
          vals.reverse.inject(0){|b, v|(b << 1 | (v ? 0 : 1))}
        end
        return bitmap.pack("C*")
      end

    end
  end

  class RawRecord
    def initialize(packet, fields, encoding)
      @packet, @fields, @encoding = packet, fields, encoding
    end

    def to_a
      @fields.map do |f|
        if s = @packet.lcs
          unless f.type == Field::TYPE_BIT or f.charsetnr == Charset::BINARY_CHARSET_NUMBER
            s = Charset.convert_encoding(s, @encoding)
          end
        end
        s
      end
    end
  end

  class StmtRawRecord
    # === Argument
    # pkt     :: [Packet]
    # fields  :: [Array of Fields]
    # encoding:: [Encoding]
    def initialize(packet, fields, encoding)
      @packet, @fields, @encoding = packet, fields, encoding
    end

    # Parse statement result packet
    # === Return
    # [Array of Object] one record
    def parse_record_packet
      @packet.utiny  # skip first byte
      null_bit_map = @packet.read((@fields.length+7+2)/8).unpack("b*").first
      rec = @fields.each_with_index.map do |f, i|
        if null_bit_map[i+2] == ?1
          nil
        else
          unsigned = f.flags & Field::UNSIGNED_FLAG != 0
          v = Protocol.net2value(@packet, f.type, unsigned)
          if v.is_a? Numeric or v.is_a? RbMysql::Time
            v
          elsif f.type == Field::TYPE_BIT or f.charsetnr == Charset::BINARY_CHARSET_NUMBER
            Charset.to_binary(v)
          else
            Charset.convert_encoding(v, @encoding)
          end
        end
      end
      rec
    end

    alias to_a parse_record_packet

  end
end
