# -*- coding: binary -*-
#
# Author:: Michael Neumann
# Copyright:: (c) 2005 by Michael Neumann
# License:: Same as Ruby's or BSD
#

require 'postgres_msf'
require 'postgres/postgres-pr/message'
require 'postgres/postgres-pr/version'
require 'postgres/postgres-pr/scram_sha_256'
require 'uri'
require 'rex/socket'

# Namespace for Metasploit branch.
module Msf
module Db

module PostgresPR

PROTO_VERSION = 3 << 16   #196608

class AuthenticationMethodMismatch < StandardError
end

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

  def initialize(database, user, password=nil, uri = nil, proxies = nil)
    uri ||= DEFAULT_URI

    @transaction_status = nil
    @params = { 'username' => user, 'database' => database }
    establish_connection(uri, proxies)

    # Check if the password supplied is a Postgres-style md5 hash
    md5_hash_match = password.match(/^md5([a-f0-9]{32})$/)

    write_message(StartupMessage.new(PROTO_VERSION, 'user' => user, 'database' => database))

    loop do
      msg = Message.read(@conn)

      case msg
      when AuthentificationClearTextPassword
        raise ArgumentError, "no password specified" if password.nil?
        raise AuthenticationMethodMismatch, "Server expected clear text password auth" if md5_hash_match
        write_message(PasswordMessage.new(password))
      when AuthentificationCryptPassword
        raise ArgumentError, "no password specified" if password.nil?
        raise AuthenticationMethodMismatch, "Server expected crypt password auth" if md5_hash_match
        write_message(PasswordMessage.new(password.crypt(msg.salt)))
      when AuthentificationMD5Password
        raise ArgumentError, "no password specified" if password.nil?
        require 'digest/md5'

        if md5_hash_match
          m = md5_hash_match[1]
        else
          m = Digest::MD5.hexdigest(password + user)
        end
        m = Digest::MD5.hexdigest(m + msg.salt)
        m = 'md5' + m

        write_message(PasswordMessage.new(m))

      when AuthenticationSASL
        negotiate_sasl(msg, user, password)
      when UnknownAuthType
        raise "unknown auth type '#{msg.auth_type}' with buffer content:\n#{Rex::Text.to_hex_dump(msg.buffer.content)}"

      when AuthentificationKerberosV4, AuthentificationKerberosV5, AuthentificationSCMCredential
        raise "unsupported authentication"

      when AuthentificationOk
      when ErrorResponse
        handle_server_error_message(msg)
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

  def peerhost
    @conn.peerhost
  end

  def peerport
    @conn.peerport
  end

  def peerinfo
    "#{peerhost}:#{peerport}"
  end

  def current_database
    @params['database']
  end

  # List of supported PostgreSQL platforms & architectures:
  # https://postgrespro.com/docs/postgresql/16/supported-platforms
  def map_compile_os_to_platform(compile_os)
    return Msf::Platform::Unknown.realname if compile_os.blank?

    compile_os = compile_os.downcase.encode(::Encoding::BINARY)

    if compile_os.match?('linux')
      platform = Msf::Platform::Linux
    elsif compile_os.match?(/(darwin|mac|osx)/)
      platform = Msf::Platform::OSX
    elsif compile_os.match?('win')
      platform = Msf::Platform::Windows
    elsif compile_os.match?('free')
      platform = Msf::Platform::FreeBSD
    elsif compile_os.match?('net')
      platform = Msf::Platform::NetBSD
    elsif compile_os.match?('open')
      platform = Msf::Platform::OpenBSD
    elsif compile_os.match?('solaris')
      platform = Msf::Platform::Solaris
    elsif compile_os.match?('aix')
      platform = Msf::Platform::AIX
    elsif compile_os.match?('hpux')
      platform = Msf::Platform::HPUX
    elsif compile_os.match?('irix')
      platform = Msf::Platform::Irix
    else
      # Return the query result if the value can't be mapped
      return compile_os
    end

    platform.realname
  end

  # List of supported PostgreSQL platforms & architectures:
  # https://postgrespro.com/docs/postgresql/16/supported-platforms
  def map_compile_arch_to_architecture(compile_arch)
    return '' if compile_arch.blank?

    compile_arch = compile_arch.downcase.encode(::Encoding::BINARY)

    if compile_arch.match?('sparc')
      if compile_arch.include?('64')
        arch = ARCH_SPARC64
      else
        arch = ARCH_SPARC
      end
    elsif compile_arch.include?('mips')
      arch = ARCH_MIPS
    elsif compile_arch.include?('ppc')
      arch = ARCH_PPC
    elsif compile_arch.match?('arm')
      if compile_arch.match?('64')
        arch = ARCH_AARCH64
      elsif compile_arch.match?('arm')
        arch = ARCH_ARMLE
      end
    elsif compile_arch.match?('64')
      arch = ARCH_X86_64
    elsif compile_arch.match?('86') || compile_arch.match?('i686')
      arch = ARCH_X86
    else
      # Return the query result if the value can't be mapped
      arch = compile_arch
    end

    arch
  end

  # @return [Hash] Detect the platform and architecture of the PostgreSQL server:
  #  * :arch [String] The server architecture.
  #  * :platform [String] The server platform.
  def detect_platform_and_arch
    result = {}

    query_result = query('select version()').rows[0][0]
    match_platform_and_arch = query_result.match(/on (?<architecture>\w+)-\w+-(?<platform>\w+)/)

    if match_platform_and_arch.nil?
      arch = platform = query_result
    else
      arch = match_platform_and_arch[:architecture]
      platform = match_platform_and_arch[:platform]
    end

    result[:arch] = map_compile_arch_to_architecture(arch)
    result[:platform] = map_compile_os_to_platform(platform)

    result
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
    write_message(Query.new(sql))

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


  # @param [AuthenticationSASL] msg
  # @param [String] user
  # @param [String,nil] password
  def negotiate_sasl(msg, user, password = nil)
    if msg.mechanisms.include?('SCRAM-SHA-256')
      scram_sha_256 = ScramSha256.new
      # Start negotiating scram, additionally wrapping in SASL and unwrapping the SASL responses
      scram_sha_256.negotiate(user, password) do |state, value|
        if state == :client_first
          sasl_initial_response_message = SaslInitialResponseMessage.new(
            mechanism: 'SCRAM-SHA-256',
            value: value
          )

          write_message(sasl_initial_response_message)

          sasl_continue = Message.read(@conn)
          raise handle_server_error_message(sasl_continue) if sasl_continue.is_a?(ErrorResponse)
          raise AuthenticationMethodMismatch, "Did not receive AuthenticationSASLContinue - instead got #{sasl_continue}" unless sasl_continue.is_a?(AuthenticationSASLContinue)

          server_first_string = sasl_continue.value
          server_first_string
        elsif state == :client_final
          sasl_initial_response_message = SASLResponseMessage.new(
            value: value
          )

          write_message(sasl_initial_response_message)

          server_final = Message.read(@conn)
          raise handle_server_error_message(server_final) if server_final.is_a?(ErrorResponse)
          raise AuthenticationMethodMismatch, "Did not receive AuthenticationSASLFinal - instead got #{server_final}" unless server_final.is_a?(AuthenticationSASLFinal)

          server_final_string = server_final.value
          server_final_string
        else
          raise AuthenticationMethodMismatch, "Unexpected negotiation state #{state}"
        end
      end
    else
      raise AuthenticationMethodMismatch, "unsupported SASL mechanisms #{msg.mechanisms.inspect}"
    end
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

  # @param [ErrorResponse] server_error_message
  # @raise [RuntimeError]
  def handle_server_error_message(server_error_message)
    raise server_error_message.field_values.join("\t")
  end

  # tcp://localhost:5432
  # unix:/tmp/.s.PGSQL.5432
  def establish_connection(uri, proxies)
    u = URI.parse(uri)
    case u.scheme
    when 'tcp'
      @conn = Rex::Socket.create(
      'PeerHost' => (u.host || DEFAULT_HOST).gsub(/[\[\]]/, ''),  # Strip any brackets off (IPv6)
      'PeerPort' => (u.port || DEFAULT_PORT),
      'proto' => 'tcp',
      'Proxies' => proxies
    )
    when 'unix'
      @conn = UNIXSocket.new(u.path)
    else
      raise 'unrecognized uri scheme format (must be tcp or unix)'
    end
  end

  # @param [Message] message
  # @return [Numeric] The byte count successfully written to the currently open connection
  def write_message(message)
    @conn << message.dump
  end
end

end # module PostgresPR

end
end
