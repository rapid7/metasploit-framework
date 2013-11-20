# -*- coding: binary -*-
require 'rex/socket'

###
#
# This class represents the set of parameters that are used to create
# a socket, whether it be a server or client socket.
#
# @example
#   nsock = Rex::Socket::Tcp.create(
#     'PeerHost'  =>  opts['RHOST'] || rhost,
#     'PeerPort'  => (opts['RPORT'] || rport).to_i,
#     'LocalHost' =>  opts['CHOST'] || chost || "0.0.0.0",
#     'LocalPort' => (opts['CPORT'] || cport || 0).to_i,
#     'SSL'       =>  dossl,
#     'SSLVersion'=>  opts['SSLVersion'] || ssl_version,
#     'Proxies'   => proxies,
#     'Timeout'   => (opts['ConnectTimeout'] || connect_timeout || 10).to_i,
#     'Context'   =>
#       {
#         'Msf'        => framework,
#         'MsfExploit' => self,
#       })
#
###
class Rex::Socket::Parameters

  ##
  #
  # Factory
  #
  ##

  #
  # Creates an instance of the Parameters class using the supplied hash.
  #
  def self.from_hash(hash)
    return self.new(hash)
  end

  ##
  #
  # Constructor
  #
  ##

  #
  # Initializes the attributes from the supplied hash.  The following hash
  # keys can be specified.
  #
  # @option hash [String] 'PeerHost' The remote host to connect to
  # @option hash [String] 'PeerAddr' (alias for 'PeerHost')
  # @option hash [Fixnum] 'PeerPort' The remote port to connect to
  # @option hash [String] 'LocalHost' The local host to communicate from, if any
  # @option hash [String] 'LocalPort' The local port to communicate from, if any
  # @option hash [Bool] 'Bool' Create a bare socket
  # @option hash [Bool] 'Server' Whether or not this should be a server
  # @option hash [Bool] 'SSL' Whether or not SSL should be used
  # @option hash [String] 'SSLVersion' Specify SSL2, SSL3, or TLS1 (SSL3 is
  #   default)
  # @option hash [String] 'SSLCert' A file containing an SSL certificate (for
  #   server sockets)
  # @option hash [String] 'SSLCipher' see {#ssl_cipher}
  # @option hash [Bool] 'SSLCompression' enable SSL-level compression
  # @option hash [String] 'SSLVerifyMode' SSL certificate verification
  #   mechanism. One of 'NONE' (default), 'CLIENT_ONCE', 'FAIL_IF_NO_PEER_CERT ', 'PEER'
  # @option hash [String] 'Proxies' List of proxies to use.
  # @option hash [String] 'Proto' The underlying protocol to use.
  # @option hash [String] 'IPv6' Force the use of IPv6.
  # @option hash [String] 'Comm' The underlying {Comm} object to use to create
  #   the socket for this parameter set.
  # @option hash [Hash] 'Context' A context hash that can allow users of
  #   this parameter class instance to determine who is responsible for
  #   requesting that a socket be created.
  # @option hash [String] 'Retries' The number of times a connection should be
  #   retried.
  # @option hash [Fixnum] 'Timeout' The number of seconds before a connection
  #   should time out
  def initialize(hash)
    if (hash['PeerHost'])
      self.peerhost = hash['PeerHost']
    elsif (hash['PeerAddr'])
      self.peerhost = hash['PeerAddr']
    else
      self.peerhost = nil
    end

    if (hash['LocalHost'])
      self.localhost = hash['LocalHost']
    elsif (hash['LocalAddr'])
      self.localhost = hash['LocalAddr']
    else
      self.localhost = '0.0.0.0'
    end

    if (hash['PeerPort'])
      self.peerport = hash['PeerPort'].to_i
    else
      self.peerport = 0
    end

    if (hash['LocalPort'])
      self.localport = hash['LocalPort'].to_i
    else
      self.localport = 0
    end

    if (hash['Bare'])
      self.bare = hash['Bare']
    else
      self.bare = false
    end

    if (hash['SSL'] and hash['SSL'].to_s =~ /^(t|y|1)/i)
      self.ssl = true
    else
      self.ssl = false
    end

    supported_ssl_versions = ['SSL2', 'SSL23', 'TLS1', 'SSL3', :SSLv2, :SSLv3, :SSLv23, :TLSv1]
    if (hash['SSLVersion'] and supported_ssl_versions.include? hash['SSLVersion'])
      self.ssl_version = hash['SSLVersion']
    end

    supported_ssl_verifiers = %W{CLIENT_ONCE FAIL_IF_NO_PEER_CERT NONE PEER}
    if (hash['SSLVerifyMode'] and supported_ssl_verifiers.include? hash['SSLVerifyMode'])
      self.ssl_verify_mode = hash['SSLVerifyMode']
    end

    if hash['SSLCompression']
      self.ssl_compression = hash['SSLCompression']
    end

    if (hash['SSLCipher'])
      self.ssl_cipher = hash['SSLCipher']
    end

    if (hash['SSLCert'] and ::File.file?(hash['SSLCert']))
      begin
        self.ssl_cert = ::File.read(hash['SSLCert'])
      rescue ::Exception => e
        elog("Failed to read cert: #{e.class}: #{e}", LogSource)
      end
    end

    if hash['Proxies']
      self.proxies = hash['Proxies'].split('-').map{|a| a.strip}.map{|a| a.split(':').map{|b| b.strip}}
    end

    # The protocol this socket will be using
    if (hash['Proto'])
      self.proto = hash['Proto'].downcase
    else
      self.proto = 'tcp'
    end

    # Whether or not the socket should be a server
    self.server    = hash['Server'] || false

    # The communication subsystem to use to create the socket
    self.comm      = hash['Comm']

    # The context that was passed in, if any.
    self.context   = hash['Context'] || {}

    # If no comm was supplied, try to use the comm that is best fit to
    # handle the provided host based on the current routing table.
    if( self.server )
      if (self.comm == nil and self.localhost)
        self.comm  = Rex::Socket::SwitchBoard.best_comm(self.localhost)
      end
    else
      if (self.comm == nil and self.peerhost)
        self.comm  = Rex::Socket::SwitchBoard.best_comm(self.peerhost)
      end
    end

    # If we still haven't found a comm, we default to the local comm.
    self.comm      = Rex::Socket::Comm::Local if (self.comm == nil)

    # If we are a UDP server, turn off the server flag as it was only set when
    # creating the UDP socket in order to avail of the switch board above.
    if( self.server and self.proto == 'udp' )
      self.server = false
    end

    # The number of connection retries to make (client only)
    if hash['Retries']
      self.retries = hash['Retries'].to_i
    else
      self.retries = 0
    end

    # The number of seconds before a connect attempt times out (client only)
    if hash['Timeout']
      self.timeout = hash['Timeout'].to_i
    else
      self.timeout = 5
    end

    # Whether to force IPv6 addressing
    self.v6        = hash['IPv6'] || false
  end

  ##
  #
  # Conditionals
  #
  ##

  #
  # Returns true if this represents parameters for a server.
  #
  def server?
    return (server == true)
  end

  #
  # Returns true if this represents parameters for a client.
  #
  def client?
    return (server == false)
  end

  #
  # Returns true if the protocol for the parameters is TCP.
  #
  def tcp?
    return (proto == 'tcp')
  end

  #
  # Returns true if the protocol for the parameters is UDP.
  #
  def udp?
    return (proto == 'udp')
  end

  #
  # Returns true if the protocol for the parameters is IP.
  #
  def ip?
    return (proto == 'ip')
  end

  #
  # Returns true if the socket is a bare socket that does not inherit from
  # any extended Rex classes.
  #
  def bare?
    return (bare == true)
  end

  #
  # Returns true if SSL has been requested.
  #
  def ssl?
    return ssl
  end

  #
  # Returns true if IPv6 has been enabled
  #
  def v6?
    return v6
  end


  ##
  #
  # Attributes
  #
  ##

  # The remote host information, equivalent to the PeerHost parameter hash
  # key.
  # @return [String]
  attr_accessor :peerhost

  # The remote port.  Equivalent to the PeerPort parameter hash key.
  # @return [Fixnum]
  attr_accessor :peerport

  # The local host.  Equivalent to the LocalHost parameter hash key.
  # @return [String]
  attr_accessor :localhost

  # The local port.  Equivalent to the LocalPort parameter hash key.
  # @return [Fixnum]
  attr_accessor :localport

  # The protocol to to use, such as TCP.  Equivalent to the Proto parameter
  # hash key.
  # @return [String]
  attr_accessor :proto

  # Whether or not this is a server.  Equivalent to the Server parameter
  # hash key.
  # @return [Bool]
  attr_accessor :server

  # The {Comm} instance that should be used to create the underlying socket.
  # @return [Comm]
  attr_accessor :comm

  # The context hash that was passed in to the structure.  (default: {})
  # @return [Hash]
  attr_accessor :context

  # The number of attempts that should be made.
  # @return [Fixnum]
  attr_accessor :retries

  # The number of seconds before a connection attempt should time out.
  # @return [Fixnum]
  attr_accessor :timeout

  # Whether or not this is a bare (non-extended) socket instance that should
  # be created.
  # @return [Bool]
  attr_accessor :bare

  # Whether or not SSL should be used to wrap the connection.
  # @return [Bool]
  attr_accessor :ssl

  # What version of SSL to use (SSL2, SSL3, SSL23, TLS1)
  # @return [String,Symbol]
  attr_accessor :ssl_version

  # What specific SSL Cipher(s) to use, may be a string containing the cipher
  # name or an array of strings containing cipher names e.g.
  # ["DHE-RSA-AES256-SHA", "DHE-DSS-AES256-SHA"]
  # @return [String,Array]
  attr_accessor :ssl_cipher

  # The SSL certificate, in pem format, stored as a string.  See
  # {Rex::Socket::SslTcpServer#makessl}
  # @return [String]
  attr_accessor :ssl_cert

  # Enables SSL/TLS-level compression
  # @return [Bool]
  attr_accessor :ssl_compression

  #
  # The SSL context verification mechanism
  #
  attr_accessor :ssl_verify_mode

  #
  # Whether we should use IPv6
  # @return [Bool]
  attr_accessor :v6


  # List of proxies to use
  # @return [String]
  attr_accessor :proxies

  alias peeraddr  peerhost
  alias localaddr localhost
end
