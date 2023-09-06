# -*- coding: binary -*-
#
# Author:: Michael Neumann
# Copyright:: (c) 2005 by Michael Neumann
# License:: Same as Ruby's or BSD
#

require 'postgres_msf'
require 'postgres/buffer'
require 'rex/io/stream'

# Monkeypatch to preserve original code intent
# (postgres-pr originally defined read_exactly_n_bytes on IO
# as a while loop)
module Rex::IO::Stream
  def read_exactly_n_bytes(n)
    timed_read(n)
  end
end

# Namespace for Metasploit branch.
module Msf
module Db

module PostgresPR

class ParseError < RuntimeError; end
class DumpError < RuntimeError; end


# Base class representing a PostgreSQL protocol message
class Message
  # One character message-typecode to class map
  MsgTypeMap = Hash.new { UnknownMessageType }

  def self.register_message_type(type)
    raise "duplicate message type registration" if MsgTypeMap.has_key?(type)

    MsgTypeMap[type] = self

    self.const_set(:MsgType, type)
    class_eval "def message_type; MsgType end"
  end

  def self.read(stream, startup=false)
    type = stream.read_exactly_n_bytes(1) unless startup
    length = stream.read_exactly_n_bytes(4).to_s.unpack('N').first  # FIXME: length should be signed, not unsigned

    raise ParseError if (length.nil? || length < 4)

    # If we didn't read any bytes and startup was not set, then type will be nil, so don't continue.
    unless startup
      if type.nil?
        return ParseError
      end
    end

    # initialize buffer
    buffer = Buffer.of_size(startup ? length : 1+length)
    buffer.write(type) unless startup
    buffer.write_int32_network(length)
    buffer.copy_from_stream(stream, length-4)

    (startup ? StartupMessage : MsgTypeMap[type]).create(buffer)
  end

  def self.create(buffer)
    obj = allocate
    obj.parse(buffer)
    obj
  end

  def self.dump(*args)
    new(*args).dump
  end

  def dump(body_size=0)
    buffer = Buffer.of_size(5 +  body_size)
    buffer.write(self.message_type)
    buffer.write_int32_network(4 + body_size)
    yield buffer if block_given?
    raise DumpError  unless buffer.at_end?
    return buffer.content
  end

  def parse(buffer)
    buffer.position = 5
    yield buffer if block_given?
    raise ParseError, buffer.inspect unless buffer.at_end?
  end

  def self.fields(*attribs)
    names = attribs.map {|name, type| name.to_s}
    arg_list = names.join(", ")
    ivar_list = names.map {|name| "@" + name }.join(", ")
    sym_list = names.map {|name| ":" + name }.join(", ")
    class_eval %[
      attr_accessor #{ sym_list }
      def initialize(#{ arg_list })
        #{ ivar_list } = #{ arg_list }
      end
    ]
  end
end

class UnknownMessageType < Message
  def dump
    raise
  end
end

class Authentification < Message
  register_message_type 'R'

  AuthTypeMap = {}

  def self.create(buffer)
    buffer.position = 5
    authtype = buffer.read_int32_network
    unless AuthTypeMap.key? authtype
      return UnknownAuthType.new(authtype, buffer)
    end

    klass = AuthTypeMap[authtype]
    obj = klass.allocate
    obj.parse(buffer)
    obj
  end

  def self.register_auth_type(type)
    raise "duplicate auth type registration" if AuthTypeMap.has_key?(type)
    AuthTypeMap[type] = self
    self.const_set(:AuthType, type)
    class_eval "def auth_type() AuthType end"
  end

  # the dump method of class Message
  alias message__dump dump

  def dump
    super(4) do |buffer|
      buffer.write_int32_network(self.auth_type)
    end
  end

  def parse(buffer)
    super do
      auth_t = buffer.read_int32_network
      raise ParseError unless auth_t == self.auth_type
      yield if block_given?
    end
  end
end

class UnknownAuthType < Authentification
  attr_reader :auth_type
  attr_reader :buffer

  def initialize(auth_type, buffer)
    @auth_type = auth_type
    @buffer = buffer
  end
end

class AuthentificationOk < Authentification
  register_auth_type 0
end

class AuthentificationKerberosV4 < Authentification
  register_auth_type 1
end

class AuthentificationKerberosV5 < Authentification
  register_auth_type 2
end

class AuthentificationClearTextPassword < Authentification
  register_auth_type 3
end

module SaltedAuthentificationMixin
  attr_accessor :salt

  def initialize(salt)
    @salt = salt
  end

  def dump
    raise DumpError unless @salt.size == self.salt_size

    message__dump(4 + self.salt_size) do |buffer|
      buffer.write_int32_network(self.auth_type)
      buffer.write(@salt)
    end
  end

  def parse(buffer)
    super do
      @salt = buffer.read(self.salt_size)
    end
  end
end

class AuthentificationCryptPassword < Authentification
  register_auth_type 4
  include SaltedAuthentificationMixin
  def salt_size; 2 end
end


class AuthentificationMD5Password < Authentification
  register_auth_type 5
  include SaltedAuthentificationMixin
  def salt_size; 4 end
end

class AuthentificationSCMCredential < Authentification
  register_auth_type 6
end

# SASL Overview
# https://www.postgresql.org/docs/current/sasl-authentication.html
#
# Binary format:
# https://www.postgresql.org/docs/current/protocol-message-formats.html
class AuthenticationSASL < Authentification
  # Int32(10) - Specifies that SASL authentication is required.
  register_auth_type 10

  # @return [Array<String>] Name of a SASL authentication mechanisms
  attr_reader :mechanisms

  # @param [Array<String>] mechanisms
  def initialize(mechanisms: [])
    @mechanisms = mechanisms
  end

  def dump
    auth_type_byte_size = 4
    mechanism_bytes_size = mechanisms.sum(&:size) + (mechanisms.size + 1)
    message__dump(auth_type_byte_size + mechanism_bytes_size) do |buffer|
      buffer.write_int32_network(self.auth_type)
      mechanisms.each do |mechanism|
        buffer.write_cstring(mechanism)
      end
      buffer.write(Buffer::NUL)
    end
  end

  def parse(buffer)
    super do
      # The message body is a list of SASL authentication mechanisms, in the
      # server's order of preference. A zero byte is required as terminator after
      # the last authentication mechanism name.
      # https://github.com/postgres/postgres/blob/74a2dfee2255a1bace9b0053d014c4efa2823f4d/doc/src/sgml/protocol.sgml#L3584-L3602
      @mechanisms ||= []
      while buffer.peek != Buffer::NUL
        @mechanisms << buffer.read_cstring
      end
      _null = buffer.read(1)
    end
  end
end

# AuthenticationSASLContinue (B)
# https://www.postgresql.org/docs/current/protocol-message-formats.html
class AuthenticationSASLContinue < Authentification
  # Int32(11) - Specifies that this message contains a SASL challenge.
  register_auth_type 11

  # @return [String] SASL data, specific to the SASL mechanism being used.
  attr_reader :value

  # @param [String, nil] value
  def initialize(value: nil)
    @value = value
  end

  def dump
    auth_type_byte_size = 4
    value_size = value.size
    message__dump(auth_type_byte_size + value_size) do |buffer|
      buffer.write_int32_network(self.auth_type)
      buffer.write(value)
    end
  end

  def parse(buffer)
    super do
      @value = buffer.read_rest
    end
  end
end

# AuthenticationSASLFinal (B)
# https://www.postgresql.org/docs/current/protocol-message-formats.html
class AuthenticationSASLFinal < Authentification
  # Int32(11) - Specifies that this message contains a SASL challenge.
  register_auth_type 12

  # @return [String] SASL outcome "additional data", specific to the SASL mechanism being used.
  attr_reader :value

  # @param [String] value
  def initialize(value:)
    @value = value
  end

  def dump
    auth_type_byte_size = 4
    value_size = value.size
    message__dump(auth_type_byte_size + value_size) do |buffer|
      buffer.write_int32_network(self.auth_type)
      buffer.write(value)
    end
  end

  def parse(buffer)
    super do
      @value = buffer.read_rest
    end
  end
end

class PasswordResponseMessage < Message
  # Identifies the message as a password response. Note that this is also used for GSSAPI, SSPI and SASL response messages.
  # The exact message type can be deduced from the context.
  register_message_type 'p'
end

class PasswordMessage < PasswordResponseMessage
  fields :password

  def dump
    super(@password.size + 1) do |buffer|
      buffer.write_cstring(@password)
    end
  end

  def parse(buffer)
    super do
      @password = buffer.read_cstring
    end
  end
end

# SASLInitialResponse (F). The client sends a SASLInitialResponse after choosing a SASL mechanism. The message includes the name of the selected
# mechanism, and an optional Initial Client Response, if the selected mechanism uses that.
#
# https://www.postgresql.org/docs/current/protocol-message-formats.html
# https://www.postgresql.org/docs/current/sasl-authentication.html
class SaslInitialResponseMessage < PasswordResponseMessage

  # @return [String] Name of the SASL authentication mechanism that the client selected.
  attr_reader :mechanism

  # @return [String] SASL mechanism specific "Initial Response" - specific to the SASL mechanism used
  attr_reader :value

  # @param [String] mechanism
  # @param [String] value
  def initialize(mechanism: nil, value: nil)
    @mechanism = mechanism
    @value = value
  end

  def dump
    mechanism_size = mechanism.size + Buffer::NUL.size
    value_size_prefix_size = 4
    value_size = value.size
    message_size = mechanism_size + value_size_prefix_size + value_size

    super(message_size) do |buffer|
      buffer.write_cstring(mechanism)
      buffer.write_int32_network(value_size)
      buffer.write(value)
    end
  end

  def parse(buffer)
    super do
      @mechanism = buffer.read_cstring
      _value_size_prefix_size = buffer.read_int32_network
      @value = buffer.read_rest
    end
  end

  def ==(other)
    self.class == other.class &&
      @mechanism == other.mechanism &&
      @value == other.value
  end
end

# SASLResponse (F)
#
# https://www.postgresql.org/docs/current/protocol-message-formats.html
# https://www.postgresql.org/docs/current/sasl-authentication.html
class SASLResponseMessage < PasswordResponseMessage

  # @return [String] SASL mechanism specific "Initial Response" - specific to the SASL mechanism used
  attr_reader :value

  # @param [String] value
  def initialize(value: nil)
    @value = value
  end

  def dump
    super(value.size) do |buffer|
      buffer.write(value)
    end
  end

  def parse(buffer)
    super do
      @value = buffer.read_rest
    end
  end

  def ==(other)
    self.class == other.class &&
      @value == other.value
  end
end

class ParameterStatus < Message
  register_message_type 'S'
  fields :key, :value

  def dump
    super(@key.size + 1 + @value.size + 1) do |buffer|
      buffer.write_cstring(@key)
      buffer.write_cstring(@value)
    end
  end

  def parse(buffer)
    super do
      @key = buffer.read_cstring
      @value = buffer.read_cstring
    end
  end
end

class BackendKeyData < Message
  register_message_type 'K'
  fields :process_id, :secret_key

  def dump
    super(4 + 4) do |buffer|
      buffer.write_int32_network(@process_id)
      buffer.write_int32_network(@secret_key)
    end
  end

  def parse(buffer)
    super do
      @process_id = buffer.read_int32_network
      @secret_key = buffer.read_int32_network
    end
  end
end

class ReadyForQuery < Message
  register_message_type 'Z'
  fields :backend_transaction_status_indicator

  def dump
    super(1) do |buffer|
      buffer.write_byte(@backend_transaction_status_indicator)
    end
  end

  def parse(buffer)
    super do
      @backend_transaction_status_indicator = buffer.read_byte
    end
  end
end

class DataRow < Message
  register_message_type 'D'
  fields :columns

  def dump
    sz = @columns.inject(2) {|sum, col| sum + 4 + (col ? col.size : 0)}
    super(sz) do |buffer|
      buffer.write_int16_network(@columns.size)
      @columns.each {|col|
        buffer.write_int32_network(col ? col.size : -1)
        buffer.write(col) if col
      }
    end
  end

  def parse(buffer)
    super do
      n_cols = buffer.read_int16_network
      @columns = (1..n_cols).collect {
        len = buffer.read_int32_network
        if len == -1
          nil
        else
          buffer.read(len)
        end
      }
    end
  end
end

class CommandComplete < Message
  register_message_type 'C'
  fields :cmd_tag

  def dump
    super(@cmd_tag.size + 1) do |buffer|
      buffer.write_cstring(@cmd_tag)
    end
  end

  def parse(buffer)
    super do
      @cmd_tag = buffer.read_cstring
    end
  end
end

class EmptyQueryResponse < Message
  register_message_type 'I'
end

module NoticeErrorMixin
  attr_accessor :field_type, :field_values

  def initialize(field_type=0, field_values=[])
    raise ArgumentError if field_type == 0 and not field_values.empty?
    @field_type, @field_values = field_type, field_values
  end

  def dump
    raise ArgumentError if @field_type == 0 and not @field_values.empty?

    sz = 1
    sz += @field_values.inject(1) {|sum, fld| sum + fld.size + 1} unless @field_type == 0

    super(sz) do |buffer|
      buffer.write_byte(@field_type)
      break if @field_type == 0
      @field_values.each {|fld| buffer.write_cstring(fld) }
      buffer.write_byte(0)
    end
  end

  def parse(buffer)
    super do
      @field_type = buffer.read_byte
      break if @field_type == 0
      @field_values = []
      while buffer.position < buffer.size-1
        @field_values << buffer.read_cstring
      end
      terminator = buffer.read_byte
      raise ParseError unless terminator == 0
    end
  end
end

class NoticeResponse < Message
  register_message_type 'N'
  include NoticeErrorMixin
end

class ErrorResponse < Message
  register_message_type 'E'
  include NoticeErrorMixin
end

# TODO
class CopyInResponse < Message
  register_message_type 'G'
end

# TODO
class CopyOutResponse < Message
  register_message_type 'H'
end

class Parse < Message
  register_message_type 'P'
  fields :query, :stmt_name, :parameter_oids

  def initialize(query, stmt_name="", parameter_oids=[])
    @query, @stmt_name, @parameter_oids = query, stmt_name, parameter_oids
  end

  def dump
    sz = @stmt_name.size + 1 + @query.size + 1 + 2 + (4 * @parameter_oids.size)
    super(sz) do |buffer|
      buffer.write_cstring(@stmt_name)
      buffer.write_cstring(@query)
      buffer.write_int16_network(@parameter_oids.size)
      @parameter_oids.each {|oid| buffer.write_int32_network(oid) }
    end
  end

  def parse(buffer)
    super do
      @stmt_name = buffer.read_cstring
      @query = buffer.read_cstring
      n_oids = buffer.read_int16_network
      @parameter_oids = (1..n_oids).collect {
        # TODO: zero means unspecified. map to nil?
        buffer.read_int32_network
      }
    end
  end
end

class ParseComplete < Message
  register_message_type '1'
end

class Query < Message
  register_message_type 'Q'
  fields :query

  def dump
    super(@query.size + 1) do |buffer|
      buffer.write_cstring(@query)
    end
  end

  def parse(buffer)
    super do
      @query = buffer.read_cstring
    end
  end
end

class RowDescription < Message
  register_message_type 'T'
  fields :fields

  class FieldInfo < Struct.new(:name, :oid, :attr_nr, :type_oid, :typlen, :atttypmod, :formatcode); end

  def dump
    sz = @fields.inject(2) {|sum, fld| sum + 18 + fld.name.size + 1 }
    super(sz) do |buffer|
      buffer.write_int16_network(@fields.size)
      @fields.each { |f|
        buffer.write_cstring(f.name)
        buffer.write_int32_network(f.oid)
        buffer.write_int16_network(f.attr_nr)
        buffer.write_int32_network(f.type_oid)
        buffer.write_int16_network(f.typlen)
        buffer.write_int32_network(f.atttypmod)
        buffer.write_int16_network(f.formatcode)
      }
    end
  end

  def parse(buffer)
    super do
      n_fields = buffer.read_int16_network
      @fields = (1..n_fields).collect {
        f = FieldInfo.new
        f.name       = buffer.read_cstring
        f.oid        = buffer.read_int32_network
        f.attr_nr    = buffer.read_int16_network
        f.type_oid   = buffer.read_int32_network
        f.typlen     = buffer.read_int16_network
        f.atttypmod  = buffer.read_int32_network
        f.formatcode = buffer.read_int16_network
        f
      }
    end
  end
end

class StartupMessage < Message
  fields :proto_version, :params

  def dump
    sz = @params.inject(4 + 4) {|sum, kv| sum + kv[0].size + 1 + kv[1].size + 1} + 1

    buffer = Buffer.of_size(sz)
    buffer.write_int32_network(sz)
    buffer.write_int32_network(@proto_version)
    @params.each_pair {|key, value|
      buffer.write_cstring(key)
      buffer.write_cstring(value)
    }
    buffer.write_byte(0)

    raise DumpError unless buffer.at_end?
    return buffer.content
  end

  def parse(buffer)
    buffer.position = 4

    @proto_version = buffer.read_int32_network
    @params = {}

    while buffer.position < buffer.size-1
      key = buffer.read_cstring
      val = buffer.read_cstring
      @params[key] = val
    end

    nul = buffer.read_byte
    raise ParseError unless nul == 0
    raise ParseError unless buffer.at_end?
  end
end

class SSLRequest < Message
  fields :ssl_request_code

  def dump
    sz = 4 + 4
    buffer = Buffer.of_size(sz)
    buffer.write_int32_network(sz)
    buffer.write_int32_network(@ssl_request_code)
    raise DumpError unless buffer.at_end?
    return buffer.content
  end

  def parse(buffer)
    buffer.position = 4
    @ssl_request_code = buffer.read_int32_network
    raise ParseError unless buffer.at_end?
  end
end

=begin
# TODO: duplicate message-type, split into client/server messages
class Sync < Message
  register_message_type 'S'
end
=end

class Terminate < Message
  register_message_type 'X'
end

end # module PostgresPR

end
end
