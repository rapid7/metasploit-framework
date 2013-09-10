# -*- coding: binary -*-
# Copyright (C) 2008-2009 TOMITA Masahiro
# mailto:tommy@tmtm.org

require "socket"
require "timeout"
require "digest/sha1"
require "thread"
require "stringio"

class RbMysql
  # MySQL network protocol
  class Protocol

    VERSION = 10
    MAX_PACKET_LENGTH = 2**24-1

    # convert Numeric to LengthCodedBinary
    def self.lcb(num)
      return "\xfb" if num.nil?
      return [num].pack("C") if num < 251
      return [252, num].pack("Cv") if num < 65536
      return [253, num&0xffff, num>>16].pack("CvC") if num < 16777216
      return [254, num&0xffffffff, num>>32].pack("CVV")
    end

    # convert String to LengthCodedString
    def self.lcs(str)
      str = Charset.to_binary str
      lcb(str.length)+str
    end

    # convert LengthCodedBinary to Integer
    # === Argument
    # lcb :: [String] LengthCodedBinary. This value will be broken.
    # === Return
    # Integer or nil
    def self.lcb2int!(lcb)
      return nil if lcb.empty?
      case v = lcb.slice!(0)
      when ?\xfb
        return nil
      when ?\xfc
        return lcb.slice!(0,2).unpack("v").first
      when ?\xfd
        c, v = lcb.slice!(0,3).unpack("Cv")
        return (v << 8)+c
      when ?\xfe
        v1, v2 = lcb.slice!(0,8).unpack("VV")
        return (v2 << 32)+v1
      else
        return v.ord
      end
    end

    # convert LengthCodedString to String
    # === Argument
    # lcs :: [String] LengthCodedString. This value will be broken.
    # === Return
    # String or nil
    def self.lcs2str!(lcs)
      len = lcb2int! lcs
      return len && lcs.slice!(0, len)
    end

    def self.eof_packet?(data)
      data[0] == ?\xfe && data.length == 5
    end

    # Convert netdata to Ruby value
    # === Argument
    # data :: [String] packet data. This will be broken.
    # type :: [Integer] field type
    # unsigned :: [true or false] true if value is unsigned
    # === Return
    # Object :: converted value.
    def self.net2value(data, type, unsigned)
      case type
      when Field::TYPE_STRING, Field::TYPE_VAR_STRING, Field::TYPE_NEWDECIMAL, Field::TYPE_BLOB
        return Protocol.lcs2str!(data)
      when Field::TYPE_TINY
        v = data.slice!(0).ord
        return unsigned ? v : v < 128 ? v : v-256
      when Field::TYPE_SHORT
        v = data.slice!(0,2).unpack("v").first
        return unsigned ? v : v < 32768 ? v : v-65536
      when Field::TYPE_INT24, Field::TYPE_LONG
        v = data.slice!(0,4).unpack("V").first
        return unsigned ? v : v < 2**32/2 ? v : v-2**32
      when Field::TYPE_LONGLONG
        n1, n2 = data.slice!(0,8).unpack("VV")
        v = (n2 << 32) | n1
        return unsigned ? v : v < 2**64/2 ? v : v-2**64
      when Field::TYPE_FLOAT
        return data.slice!(0,4).unpack("e").first
      when Field::TYPE_DOUBLE
        return data.slice!(0,8).unpack("E").first
      when Field::TYPE_DATE, Field::TYPE_DATETIME, Field::TYPE_TIMESTAMP
        len = data.slice!(0).ord
        y, m, d, h, mi, s, bs = data.slice!(0,len).unpack("vCCCCCV")
        return RbMysql::Time.new(y, m, d, h, mi, s, bs)
      when Field::TYPE_TIME
        len = data.slice!(0).ord
        sign, d, h, mi, s, sp = data.slice!(0,len).unpack("CVCCCV")
        h = d.to_i * 24 + h.to_i
        return RbMysql::Time.new(0, 0, 0, h, mi, s, sign!=0, sp)
      when Field::TYPE_YEAR
        return data.slice!(0,2).unpack("v").first
      when Field::TYPE_BIT
        return Protocol.lcs2str!(data)
      else
        raise "not implemented: type=#{type}"
      end
    end

    # convert Ruby value to netdata
    # === Argument
    # v :: [Object] Ruby value.
    # === Return
    # String :: netdata
    # === Exception
    # ProtocolError :: value too large / value is not supported
    def self.value2net(v)
      case v
      when nil
        type = Field::TYPE_NULL
        val = ""
      when Integer
        if v >= 0
          if v < 256
            type = Field::TYPE_TINY | 0x8000
            val = [v].pack("C")
          elsif v < 256**2
            type = Field::TYPE_SHORT | 0x8000
            val = [v].pack("v")
          elsif v < 256**4
            type = Field::TYPE_LONG | 0x8000
            val = [v].pack("V")
          elsif v < 256**8
            type = Field::TYPE_LONGLONG | 0x8000
            val = [v&0xffffffff, v>>32].pack("VV")
          else
            raise ProtocolError, "value too large: #{v}"
          end
        else
          if -v <= 256/2
            type = Field::TYPE_TINY
            val = [v].pack("C")
          elsif -v <= 256**2/2
            type = Field::TYPE_SHORT
            val = [v].pack("v")
          elsif -v <= 256**4/2
            type = Field::TYPE_LONG
            val = [v].pack("V")
          elsif -v <= 256**8/2
            type = Field::TYPE_LONGLONG
            val = [v&0xffffffff, v>>32].pack("VV")
          else
            raise ProtocolError, "value too large: #{v}"
          end
        end
      when Float
        type = Field::TYPE_DOUBLE
        val = [v].pack("E")
      when String
        type = Field::TYPE_STRING
        val = Protocol.lcs(v)
      when RbMysql::Time, ::Time
        type = Field::TYPE_DATETIME
        val = [7, v.year, v.month, v.day, v.hour, v.min, v.sec].pack("CvCCCCC")
      else
        raise ProtocolError, "class #{v.class} is not supported"
      end
      return type, val
    end

    attr_reader :sqlstate

    # make socket connection to server.
    # === Argument
    # host :: [String] if "localhost" or "" nil then use UNIXSocket. Otherwise use TCPSocket
    # port :: [Integer] port number using by TCPSocket
    # socket :: [String] socket file name using by UNIXSocket
    # conn_timeout :: [Integer] connect timeout (sec).
    # read_timeout :: [Integer] read timeout (sec).
    # write_timeout :: [Integer] write timeout (sec).
    def initialize(host, port, socket, conn_timeout, read_timeout, write_timeout)
      begin
        Timeout.timeout conn_timeout do
          if host.nil? or host.empty? or host == "localhost"
            socket = ENV["MYSQL_UNIX_PORT"] || MYSQL_UNIX_PORT
            @sock = UNIXSocket.new socket
          else
            if !socket
              port ||= ENV["MYSQL_TCP_PORT"] || (Socket.getservbyname("mysql","tcp") rescue MYSQL_TCP_PORT)
              @sock = TCPSocket.new host, port
            else
              @sock = socket
            end
          end
        end
      rescue Timeout::Error
        raise ClientError, "connection timeout"
      end
      @read_timeout = read_timeout
      @write_timeout = write_timeout
      @seq = 0                # packet counter. reset by each command
      @mutex = Mutex.new
    end

    def close
      @sock.close
    end

    def synchronize
      @mutex.synchronize do
        return yield
      end
    end

    # Reset sequence number
    def reset
      @seq = 0
    end

    # Read one packet data
    # === Return
    # String
    # === Exception
    # ProtocolError :: invalid packet sequence number
    def read
      ret = ""
      len = nil
      begin
        Timeout.timeout @read_timeout do
          header = @sock.read(4)
          len1, len2, seq = header.unpack("CvC")
          len = (len2 << 8) + len1
          # Ignore the sequence number -- protocol differences between 4.x and 5.x
          # raise ProtocolError, "invalid packet: sequence number mismatch(#{seq} != #{@seq}(expected))" if @seq != seq
          @seq = (@seq + 1) % 256
          ret.concat @sock.read(len)
        end
      rescue Timeout::Error
        raise ClientError, "read timeout"
      end while len == MAX_PACKET_LENGTH

      @sqlstate = "00000"

      # Error packet
      if ret[0] == ?\xff
        f, errno, marker, @sqlstate, message = ret.unpack("Cvaa5a*")
        unless marker == "#"
          f, errno, message = ret.unpack("Cva*")    # Version 4.0 Error
          @sqlstate = ""
        end
        if RbMysql::ServerError::ERROR_MAP.key? errno
          raise RbMysql::ServerError::ERROR_MAP[errno].new(message, @sqlstate)
        end
        raise RbMysql::ServerError.new(message, @sqlstate)
      end
      ret
    end

    # Write one packet data
    # === Argument
    # data [String / IO] ::
    def write(data)
      begin
        @sock.sync = false
        data = StringIO.new data if data.is_a? String
        while d = data.read(MAX_PACKET_LENGTH)
          Timeout.timeout @write_timeout do
            @sock.write [d.length%256, d.length/256, @seq].pack("CvC")
            @sock.write d
          end
          @seq = (@seq + 1) % 256
        end
        @sock.sync = true
        Timeout.timeout @write_timeout do
          @sock.flush
        end
      rescue Timeout::Error
        raise ClientError, "write timeout"
      end
    end

    # Send one packet
    # === Argument
    # packet :: [*Packet]
    def send_packet(packet)
      write packet.serialize
    end

    # Read EOF packet
    # === Exception
    # ProtocolError :: packet is not EOF
    def read_eof_packet
      data = read
      # EOF packet is different between MySQL 4.x and 5.x, so ignore.
      # raise ProtocolError, "packet is not EOF" unless Protocol.eof_packet? data
    end

    # Read initial packet
    # === Return
    # InitialPacket ::
    # === Exception
    # ProtocolError :: invalid packet
    def read_initial_packet
      InitialPacket.parse read
    end

    # Read result packet
    # === Return
    # ResultPacket ::
    def read_result_packet
      ResultPacket.parse read
    end

    # Read field packet
    # === Return
    # FieldPacket :: packet data
    # === Exception
    # ProtocolError :: invalid packet
    def read_field_packet
      FieldPacket.parse read
    end

    # Read prepare result packet
    # === Return
    # PrepareResultPacket ::
    # === Exception
    # ProtocolError :: invalid packet
    def read_prepare_result_packet
      PrepareResultPacket.parse read
    end

    # client->server packet base class
    class TxPacket
    end

    # server->client packet base class
    class RxPacket
    end

    # Initial packet
    class InitialPacket < RxPacket
      def self.parse(data)
        protocol_version, server_version, thread_id, scramble_buff, f0,
        server_capabilities, server_charset, server_status, f1,
        rest_scramble_buff = data.unpack("CZ*Va8CvCva13Z13")
        raise ProtocolError, "unsupported version: #{protocol_version}" unless protocol_version == VERSION
        raise ProtocolError, "invalid packet: f0=#{f0}" unless f0 == 0
        # Remove the f1 check to backport https://github.com/tmtm/ruby-mysql/commit/07ddfafafbd1d46bbb71c7cb54ae0f03bc998d27
        # raise ProtocolError, "invalid packet: f1=#{f1.inspect}" unless f1 == "\0\0\0\0\0\0\0\0\0\0\0\0\0"
        scramble_buff.concat rest_scramble_buff
        self.new protocol_version, server_version, thread_id, server_capabilities, server_charset, server_status, scramble_buff
      end

      attr_accessor :protocol_version, :server_version, :thread_id, :server_capabilities, :server_charset, :server_status, :scramble_buff

      def initialize(*args)
        @protocol_version, @server_version, @thread_id, @server_capabilities, @server_charset, @server_status, @scramble_buff = args
      end

      def crypt_password(plain)
        return "" if plain.nil? or plain.empty?
        hash_stage1 = Digest::SHA1.digest plain
        hash_stage2 = Digest::SHA1.digest hash_stage1
        return hash_stage1.unpack("C*").zip(Digest::SHA1.digest(@scramble_buff+hash_stage2).unpack("C*")).map{|a,b| a^b}.pack("C*")
      end
    end

    # Authentication packet
    class AuthenticationPacket < TxPacket
      attr_accessor :client_flags, :max_packet_size, :charset_number, :username, :scrambled_password, :databasename

      def initialize(*args)
        @client_flags, @max_packet_size, @charset_number, @username, @scrambled_password, @databasename = args
      end

      def serialize
        [
          client_flags,
          max_packet_size,
          Protocol.lcb(charset_number),
          "",                   # always 0x00 * 23
          username,
          Protocol.lcs(scrambled_password),
          databasename
        ].pack("VVa*a23Z*A*Z*")
      end
    end

    # Quit packet
    class QuitPacket < TxPacket
      def serialize
        [COM_QUIT].pack("C")
      end
    end

    # Query packet
    class QueryPacket < TxPacket
      attr_accessor :query

      def initialize(*args)
        @query, = args
      end

      def serialize
        [COM_QUERY, query].pack("Ca*")
      end
    end

    # Result packet
    class ResultPacket < RxPacket
      def self.parse(data)
        field_count = Protocol.lcb2int! data
        if field_count == 0
          affected_rows = Protocol.lcb2int! data
          insert_id = Protocol.lcb2int!(data)
          server_status, warning_count, message = data.unpack("vva*")
          return self.new(field_count, affected_rows, insert_id, server_status, warning_count, message)
        else
          return self.new(field_count)
        end
      end

      attr_accessor :field_count, :affected_rows, :insert_id, :server_status, :warning_count, :message

      def initialize(*args)
        @field_count, @affected_rows, @insert_id, @server_status, @warning_count, @message = args
      end
    end

    # Field packet
    class FieldPacket < RxPacket
      def self.parse(data)
        first = Protocol.lcs2str! data
        db = Protocol.lcs2str! data
        table = Protocol.lcs2str! data
        org_table = Protocol.lcs2str! data
        name = Protocol.lcs2str! data
        org_name = Protocol.lcs2str! data
        f0, charsetnr, length, type, flags, decimals, f1, data = data.unpack("CvVCvCva*")
        raise ProtocolError, "invalid packet: f1=#{f1}" unless f1 == 0
        default = Protocol.lcs2str! data
        return self.new(db, table, org_table, name, org_name, charsetnr, length, type, flags, decimals, default)
      end

      attr_accessor :db, :table, :org_table, :name, :org_name, :charsetnr, :length, :type, :flags, :decimals, :default

      def initialize(*args)
        @db, @table, @org_table, @name, @org_name, @charsetnr, @length, @type, @flags, @decimals, @default = args
      end
    end

    # Prepare packet
    class PreparePacket < TxPacket
      attr_accessor :query

      def initialize(*args)
        @query, = args
      end

      def serialize
        [COM_STMT_PREPARE, query].pack("Ca*")
      end
    end

    # Prepare result packet
    class PrepareResultPacket < RxPacket
      def self.parse(data)
        raise ProtocolError, "invalid packet" unless data.slice!(0) == ?\0
        statement_id, field_count, param_count, f, warning_count = data.unpack("VvvCv")
        raise ProtocolError, "invalid packet" unless f == 0x00
        self.new statement_id, field_count, param_count, warning_count
      end

      attr_accessor :statement_id, :field_count, :param_count, :warning_count

      def initialize(*args)
        @statement_id, @field_count, @param_count, @warning_count = args
      end
    end

    # Execute packet
    class ExecutePacket < TxPacket
      attr_accessor :statement_id, :cursor_type, :values

      def initialize(*args)
        @statement_id, @cursor_type, @values = args
      end

      def serialize
        nbm = null_bitmap values
        netvalues = ""
        types = values.map do |v|
          t, n = Protocol.value2net v
          netvalues.concat n if v
          t
        end
        [RbMysql::COM_STMT_EXECUTE, statement_id, cursor_type, 1, nbm, 1, types.pack("v*"), netvalues].pack("CVCVa*Ca*a*")
      end

      private

      # make null bitmap
      #
      # If values is [1, nil, 2, 3, nil] then returns "\x12"(0b10010).
      def null_bitmap(values)
        bitmap = values.enum_for(:each_slice,8).map do |vals|
          vals.reverse.inject(0){|b, v|(b << 1 | (v ? 0 : 1))}
        end
        return bitmap.pack("C*")
      end

    end

    # Fetch packet
    class FetchPacket < TxPacket
      attr_accessor :statement_id, :fetch_length

      def initialize(*args)
        @statement_id, @fetch_length = args
      end

      def serialize
        [RbMysql::COM_STMT_FETCH, statement_id, fetch_length].pack("CVV")
      end
    end

    # Stmt close packet
    class StmtClosePacket < TxPacket
      attr_accessor :statement_id

      def initialize(*args)
        @statement_id, = args
      end

      def serialize
        [RbMysql::COM_STMT_CLOSE, statement_id].pack("CV")
      end
    end

    class FieldListPacket < TxPacket
      attr_accessor :table, :field

      def initialize(*args)
        @table, @field = args
      end

      def serialize
        [RbMysql::COM_FIELD_LIST, "#{@table}\0#{@field}"].pack("Ca*")
      end
    end
  end
end

