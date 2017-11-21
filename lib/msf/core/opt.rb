# -*- coding: binary -*-

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
    def self.CHOST(default=nil, required=false, desc="The local client address")
      Msf::OptAddress.new(__method__.to_s, [ required, desc, default ])
    end

    # @return [OptPort]
    def self.CPORT(default=nil, required=false, desc="The local client port")
      Msf::OptPort.new(__method__.to_s, [ required, desc, default ])
    end

    # @return [OptAddress]
    def self.LHOST(default=nil, required=true, desc="The listen address")
      Msf::OptAddressLocal.new(__method__.to_s, [ required, desc, default ])
    end

    # @return [OptPort]
    def self.LPORT(default=nil, required=true, desc="The listen port")
      Msf::OptPort.new(__method__.to_s, [ required, desc, default ])
    end

    # @return [OptString]
    def self.Proxies(default=nil, required=false, desc="A proxy chain of format type:host:port[,type:host:port][...]")
      Msf::OptString.new(__method__.to_s, [ required, desc, default ])
    end

    # @return [OptAddress]
    def self.RHOST(default=nil, required=true, desc="The target address")
      Msf::OptAddress.new(__method__.to_s, [ required, desc, default ])
    end

    # @return [OptPort]
    def self.RPORT(default=nil, required=true, desc="The target port")
      Msf::OptPort.new(__method__.to_s, [ required, desc, default ])
    end

    def self.ssl_supported_options
      @m ||= ['Auto', 'TLS'] + OpenSSL::SSL::SSLContext::METHODS \
             .select{|m| !m.to_s.include?('client') && !m.to_s.include?('server')} \
             .select{|m| OpenSSL::SSL::SSLContext.new(m) && true rescue false} \
             .map{|m| m.to_s.sub(/v/, '').sub('_', '.')}
    end

    # @return [OptEnum]
    def self.SSLVersion
      Msf::OptEnum.new('SSLVersion',
        'Specify the version of SSL/TLS to be used (Auto, TLS and SSL23 are auto-negotiate)',
        enums: self.ssl_supported_options
      )
    end

    CHOST = CHOST()
    CPORT = CPORT()
    LHOST = LHOST()
    LPORT = LPORT()
    Proxies = Proxies()
    RHOST = RHOST()
    RPORT = RPORT()
    SSLVersion = SSLVersion()
  end
end
