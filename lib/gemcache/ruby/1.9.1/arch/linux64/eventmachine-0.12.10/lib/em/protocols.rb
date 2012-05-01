module EventMachine
  # This module contains various protocol implementations, including:
  # - HttpClient and HttpClient2
  # - Stomp
  # - Memcache
  # - SmtpClient and SmtpServer
  # - SASLauth and SASLauthclient
  # - LineAndTextProtocol and LineText2
  # - HeaderAndContentProtocol
  # - Postgres3
  # - ObjectProtocol
  #
  # The protocol implementations live in separate files in the protocols/ subdirectory,
  # but are auto-loaded when they are first referenced in your application.
  #
  # EventMachine::Protocols is also aliased to EM::P for easier usage.
  #
  module Protocols
    # TODO : various autotools are completely useless with the lack of naming
    # convention, we need to correct that!
    autoload :TcpConnectTester, 'em/protocols/tcptest'
    autoload :HttpClient, 'em/protocols/httpclient'
    autoload :HttpClient2, 'em/protocols/httpclient2'
    autoload :LineAndTextProtocol, 'em/protocols/line_and_text'
    autoload :HeaderAndContentProtocol, 'em/protocols/header_and_content'
    autoload :LineText2, 'em/protocols/linetext2'
    autoload :Stomp, 'em/protocols/stomp'
    autoload :SmtpClient, 'em/protocols/smtpclient'
    autoload :SmtpServer, 'em/protocols/smtpserver'
    autoload :SASLauth, 'em/protocols/saslauth'
    autoload :Memcache, 'em/protocols/memcache'
    autoload :Postgres3, 'em/protocols/postgres3'
    autoload :ObjectProtocol, 'em/protocols/object_protocol'
    autoload :Socks4, 'em/protocols/socks4'
  end
end
