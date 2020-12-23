# -*- coding: binary -*-
require 'rex/payloads/meterpreter/config'
module Msf
  #
  # Builtin framework options with shortcut methods
  #
  # @example
  #   register_options(
  #     [
  #       Opt::RHOST,
  #       Opt::RPORT(21),
  #     ]
  #   )
  #   register_advanced_options([Opt::Proxies])
  #
  module Opt
    # @return [OptAddress]
    def self.CHOST(default = nil, required = false, desc = 'The local client address')
      Msf::OptAddress.new(__method__.to_s, [ required, desc, default ])
    end

    # @return [OptPort]
    def self.CPORT(default = nil, required = false, desc = 'The local client port')
      Msf::OptPort.new(__method__.to_s, [ required, desc, default ])
    end

    # @return [OptAddressLocal]
    def self.LHOST(default = nil, required = true, desc = 'The listen address (an interface may be specified)')
      Msf::OptAddressLocal.new(__method__.to_s, [ required, desc, default ])
    end

    # @return [OptPort]
    def self.LPORT(default = nil, required = true, desc = 'The listen port')
      Msf::OptPort.new(__method__.to_s, [ required, desc, default ])
    end

    # @return [OptString]
    def self.Proxies(default = nil, required = false, desc = 'A proxy chain of format type:host:port[,type:host:port][...]')
      Msf::OptString.new(__method__.to_s, [ required, desc, default ])
    end

    # @return [OptAddressRange]
    def self.RHOSTS(default = nil, required = true, desc = "The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'")
      Msf::OptAddressRange.new('RHOSTS', [ required, desc, default ])
    end

    def self.RHOST(default = nil, required = true, desc = "The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'")
      Msf::OptAddressRange.new('RHOSTS', [ required, desc, default ], aliases: [ 'RHOST' ])
    end

    # @return [OptPort]
    def self.RPORT(default = nil, required = true, desc = 'The target port')
      Msf::OptPort.new(__method__.to_s, [ required, desc, default ])
    end

    # @return [OptEnum]
    def self.SSLVersion
      Msf::OptEnum.new('SSLVersion',
                       'Specify the version of SSL/TLS to be used (Auto, TLS and SSL23 are auto-negotiate)',
                       enums: Rex::Socket::SslTcp.supported_ssl_methods)
    end

    def self.RHOST_HTTP_URL(default = nil, required = false, desc = 'The target URL, only applicable if there is a single URL')
      Msf::OptHTTPRhostURL.new(__method__.to_s, [required, desc, default ])
    end

    def self.stager_retry_options
      [
        OptInt.new('StagerRetryCount',
                   'The number of times the stager should retry if the first connect fails',
                   default: 10,
                   aliases: ['ReverseConnectRetries']),
        OptInt.new('StagerRetryWait',
                   'Number of seconds to wait for the stager between reconnect attempts',
                   default: 5)
      ]
    end

    def self.http_proxy_options
      [
        OptString.new('HttpProxyHost', 'An optional proxy server IP address or hostname',
                      aliases: ['PayloadProxyHost']),
        OptPort.new('HttpProxyPort', 'An optional proxy server port',
                    aliases: ['PayloadProxyPort']),
        OptString.new('HttpProxyUser', 'An optional proxy server username',
                      aliases: ['PayloadProxyUser'],
                      max_length: Rex::Payloads::Meterpreter::Config::PROXY_USER_SIZE - 1),
        OptString.new('HttpProxyPass', 'An optional proxy server password',
                      aliases: ['PayloadProxyPass'],
                      max_length: Rex::Payloads::Meterpreter::Config::PROXY_PASS_SIZE - 1),
        OptEnum.new('HttpProxyType', 'The type of HTTP proxy',
                    enums: ['HTTP', 'SOCKS'],
                    aliases: ['PayloadProxyType'])
      ]
    end

    def self.http_header_options
      [
        OptString.new('HttpHostHeader', 'An optional value to use for the Host HTTP header'),
        OptString.new('HttpCookie', 'An optional value to use for the Cookie HTTP header'),
        OptString.new('HttpReferer', 'An optional value to use for the Referer HTTP header')
      ]
    end

    CHOST = CHOST()
    CPORT = CPORT()
    LHOST = LHOST()
    LPORT = LPORT()
    Proxies = Proxies()
    RHOST = RHOST()
    RHOSTS = RHOSTS()
    RHOST_HTTP_URL = RHOST_HTTP_URL()
    RPORT = RPORT()
    SSLVersion = SSLVersion()
  end
end
