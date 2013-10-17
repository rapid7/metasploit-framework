# -*- coding: binary -*-
#
# Author:: Michael Neumann
# Copyright:: (c) 2005 by Michael Neumann
# License:: Same as Ruby's or BSD
#

require 'postgres_msf'
require 'postgres/postgres-pr/message'
require 'postgres/postgres-pr/version'
require 'uri'
require 'rex/socket'

# Namespace for Metasploit branch.
module Msf
module Db

module PostgresPR

PROTO_VERSION = 3 << 16   #196608

class Connection

  # Allow easy access to these instance variables
  attr_reader :conn, :params, :transaction_status

  # A block which is called with the NoticeResponse object as parameter.
  attr_accessor :notice_processor

  #
  # Returns one of the following statuses:
  #
  #   PQTRANS_IDLE    = 0 (connection idle)
  #   PQTRANS_INTRANS = 2 (idle, within transaction block)
  #   PQTRANS_INERROR = 3 (idle, within failed transaction)
  #   PQTRANS_UNKNOWN = 4 (cannot determine status)
  #
  # Not yet implemented is:
  #
  #   PQTRANS_ACTIVE  = 1 (command in progress)
  #
  def transaction_status
    case @transaction_status
    when ?I
      0
    when ?T
      2
    when ?E
      3
    else
      4
    end
  end

  def initialize(database, user, password=nil, uri = nil)
    uri ||= DEFAULT_URI

    @transaction_status = nil
    @params = {}
    establish_connection(uri)
  
    @conn << StartupMessage.new(PROTO_VERSION, 'user' => user, 'database' => database).dump

    loop do
      msg = Message.read(@conn)

      case msg
      when AuthentificationClearTextPassword
        raise ArgumentError, "no password specified" if password.nil?
        @conn << PasswordMessage.new(password).dump

      when AuthentificationCryptPassword
        raise ArgumentError, "no password specified" if password.nil?
        @conn << PasswordMessage.new(password.crypt(msg.salt)).dump

      when AuthentificationMD5Password
        raise ArgumentError, "no password specified" if password.nil?
        require 'digest/md5'

        m = Digest::MD5.hexdigest(password + user) 
        m = Digest::MD5.hexdigest(m + msg.salt)
        m = 'md5' + m
        @conn << PasswordMessage.new(m).dump

      when AuthentificationKerberosV4, AuthentificationKerberosV5, AuthentificationSCMCredential
        raise "unsupported authentification"

      when AuthentificationOk
      when ErrorResponse
        raise msg.field_values.join("\t")
      when NoticeResponse
        @notice_processor.call(msg) if @notice_processor
      when ParameterStatus
        @params[msg.key] = msg.value
      when BackendKeyData
        # TODO
        #p msg
      when ReadyForQuery
        @transaction_status = msg.backend_transaction_status_indicator
        break
      else
        raise "unhandled message type"
      end
    end
  end

  def close
    raise "connection already closed" if @conn.nil?
    @conn.shutdown
    @conn = nil
  end

  class Result 
    attr_accessor :rows, :fields, :cmd_tag
    def initialize(rows=[], fields=[])
      @rows, @fields = rows, fields
    end
  end

  def query(sql)
    @conn << Query.dump(sql)

    result = Result.new
    errors = []

    loop do
      msg = Message.read(@conn)
      case msg
      when DataRow
        result.rows << msg.columns
      when CommandComplete
        result.cmd_tag = msg.cmd_tag
      when ReadyForQuery
        @transaction_status = msg.backend_transaction_status_indicator
        break
      when RowDescription
        result.fields = msg.fields
      when CopyInResponse
      when CopyOutResponse
      when EmptyQueryResponse
      when ErrorResponse
        # TODO
        errors << msg
      when NoticeResponse
        @notice_processor.call(msg) if @notice_processor
      else
        # TODO
      end
    end

    raise errors.map{|e| e.field_values.join("\t") }.join("\n") unless errors.empty?

    result
  end

  DEFAULT_PORT = 5432
  DEFAULT_HOST = 'localhost'
  DEFAULT_PATH = '/tmp' 
  DEFAULT_URI = 
    if RUBY_PLATFORM.include?('win')
      'tcp://' + DEFAULT_HOST + ':' + DEFAULT_PORT.to_s 
    else
      'unix:' + File.join(DEFAULT_PATH, '.s.PGSQL.' + DEFAULT_PORT.to_s)  
    end

  private

  # tcp://localhost:5432
  # unix:/tmp/.s.PGSQL.5432
  def establish_connection(uri)
    u = URI.parse(uri)
    case u.scheme
    when 'tcp'
      @conn = Rex::Socket.create(
      'PeerHost' => (u.host || DEFAULT_HOST).gsub(/[\[\]]/, ''),  # Strip any brackets off (IPv6)
      'PeerPort' => (u.port || DEFAULT_PORT),
      'proto' => 'tcp'
    )
    when 'unix'
      @conn = UNIXSocket.new(u.path)
    else
      raise 'unrecognized uri scheme format (must be tcp or unix)'
    end
  end
end

end # module PostgresPR

end
end
