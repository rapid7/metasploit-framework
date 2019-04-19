# -*- coding: binary -*-

require 'rex/proto/nuuo/client_request'
require 'rex/proto/nuuo/response'

module Rex
module Proto
module Nuuo
# This class is a representation of a nuuo client
class Client
  # @!attribute host
  #   @return [String] The nuuo server host
  attr_accessor :host
  # @!attribute port
  #   @return [Integer] The nuuo server port
  attr_accessor :port
  # @!attribute timeout
  #   @return [Integer] The connect/read timeout
  attr_accessor :timeout
  # @!attribute protocol
  #   @return [String] The transport protocol used (tcp/udp)
  attr_accessor :protocol
  # @!attribute connection
  #   @return [IO] The connection established through Rex sockets
  attr_accessor :connection
  # @!attribute context
  #   @return [Hash] The Msf context where the connection belongs to
  attr_accessor :context
  # @!attribute ncs_version
  #   @return [String] NCS version used in session
  attr_accessor :ncs_version
  # @!attribute username
  #   @return [String] Username for NCS
  attr_accessor :username
  # @!attribute password
  #   @return [String] Password for NCS user
  attr_accessor :password
  # @!attribute user_session
  #   @return [String] ID for the user session
  attr_accessor :user_session
  # @!attribute config
  #   @return [Hash] ClientRequest configuration options
  attr_accessor :config

  def initialize(opts = {})
    self.host         = opts[:host]
    self.port         = opts[:port] || 5180
    self.timeout      = opts[:timeout] || 10
    self.protocol     = opts[:protocol] || 'tcp'
    self.context      = opts[:context] || {}
    self.username     = opts[:username]
    self.password     = opts[:password]
    self.user_session = opts[:user_session]

    self.config = Nuuo::ClientRequest::DefaultConfig
  end

  # Creates a connection through a Rex socket
  #
  # @return [Rex::Socket::Tcp]
  # @raise [RuntimeError] if 'tcp' is not requested
  def connect(temp: false)
    return connection if connection && !temp
    return create_tcp_connection(temp: temp) if protocol == 'tcp'
    raise ::RuntimeError, 'Nuuo Client: Unknown transport protocol'
  end

  # Closes the connection
  def close
    if connection
      connection.shutdown
      connection.close unless connection.closed?
    end

    self.connection = nil
  end

  def send_recv(req, conn=nil, t=-1)
    send_request(req, conn)
    read_response(conn, t)
  end

  def send_request(req, conn=nil)
    conn ? conn.put(req.to_s) : connect.put(req.to_s)
  end

  def read_response(conn=nil, t=-1)
    res = Response.new
    conn = connection unless conn

    return res if not t
    Timeout.timeout((t < 0) ? nil : t) do
      parse_status = nil
      while (!conn.closed? &&
              parse_status != Response::ParseCode::Completed &&
              parse_status != Response::ParseCode::Error
      )
        begin
          buff = conn.get_once
          parse_status = res.parse(buff || '')
        rescue ::Errno::EPIPE, ::EOFError, ::IOError
          case res.state
          when Response::ParseState::ProcessingHeader
            res = nil
          when Response::ParseState::ProcessingBody
            res.error = :truncated
          end
          break
        end
      end
    end

    res
  end

  def user_session_header(opts)
    val = nil
    if opts['user_session']
      val = opts['user_session']
    elsif self.user_session
      val = self.user_session
    end
  end

  def request_ping(opts={})
    opts = self.config.merge(opts)
    opts['headers'] ||= {}
    opts['method'] = 'PING'
    session = user_session_header(opts)
    opts['headers']['User-Session-No'] = session if session

    ClientRequest.new(opts)
  end

  def request_sendlicfile(opts={})
    opts = self.config.merge(opts)
    opts['headers'] ||= {}
    opts['method'] = 'SENDLICFILE'

    session = user_session_header(opts)
    opts['headers']['User-Session-No'] = session if session
    opts['data'] = '' unless opts['data']

    opts['headers']['FileName'] = opts['file_name']
    opts['headers']['Content-Length'] = opts['data'].length

    ClientRequest.new(opts)
  end

  # GETCONFIG
  # FileName:
  # FileType: 1
  # User-Session-No: <session-no>
  # @return [ClientRequest]
  def request_getconfig(opts={})
    opts = self.config.merge(opts)
    opts['headers'] ||= {}
    opts['method'] = 'GETCONFIG'

    opts['headers']['FileName'] = opts['file_name']
    opts['headers']['FileType'] = opts['file_type'] || 1
    session = user_session_header(opts)
    opts['headers']['User-Session-No'] = session if session

    ClientRequest.new(opts)
  end

  # COMMITCONFIG
  # FileName:
  # FileType: 1
  # Content-Length
  # User-Session-No: <session-no>
  #
  # <data> filedata
  # @return [ClientRequest]
  def request_commitconfig(opts={})
    opts = self.config.merge(opts)
    opts['headers'] ||= {}
    opts['method'] = 'COMMITCONFIG'

    opts['headers']['FileName'] = opts['file_name']
    opts['headers']['FileType'] = opts['file_type'] || 1

    session = user_session_header(opts)
    opts['headers']['User-Session-No'] = session if session

    opts['data'] = '' unless opts['data']
    opts['headers']['Content-Length'] = opts['data'].length

    ClientRequest.new(opts)
  end

  # USERLOGIN
  # Version:
  # Username:
  # Password-Length:
  # TimeZone-Length: 0
  #
  # <data> password
  # @return [ClientRequest]
  def request_userlogin(opts={})
    opts = self.config.merge(opts)
    opts['headers'] ||= {}
    opts['method'] = 'USERLOGIN'

    # Account for version...
    opts['headers']['Version'] = opts['server_version']

    username = nil
    if opts['username'] && opts['username'] != ''
      username = opts['username']
    elsif self.username && self.username != ''
      username = self.username
    end

    opts['headers']['Username'] = username

    password = ''
    if opts['password'] && opts['password'] != ''
      password = opts['password']
    elsif self.password && self.password != ''
      password = self.password
    end
    opts['data'] = password
    opts['headers']['Password-Length'] = password.length

    # Need to verify if this is needed
    opts['headers']['TimeZone-Length'] = '0'

    ClientRequest.new(opts)
  end

  # GETOPENALARM NUCM/1.0
  # DeviceID: <number>
  # SourceServer: <server-id>
  # LastOne: <number>
  # @return [ClientRequest]
  def request_getopenalarm(opts={})
    opts = self.config.merge(opts)
    opts['headers'] ||= {}
    opts['method'] = 'GETOPENALARM'

    opts['headers']['DeviceID'] = opts['device_id'] || 1
    opts['headers']['SourceServer'] = opts['source_server'] || 1
    opts['headers']['LastOne'] = opts['last_one'] || 1

    ClientRequest.new(opts)
  end


  private

  # Creates a TCP connection using Rex::Socket::Tcp
  #
  # @return [Rex::Socket::Tcp]
  def create_tcp_connection(temp: false)
    tcp_connection = Rex::Socket::Tcp.create(
      'PeerHost'  => host,
      'PeerPort'  => port.to_i,
      'Context'   => context,
      'Timeout'   => timeout
    )
    self.connection = tcp_connection unless temp
    tcp_connection
  end

end
end
end
end
