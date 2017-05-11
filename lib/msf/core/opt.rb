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

    # @return [OptEnum]
    def self.SSLVersion
      Msf::OptEnum.new('SSLVersion', [ false,
        'Specify the version of SSL/TLS to be used (Auto, TLS and SSL23 are auto-negotiate)', 'Auto',
        ['Auto', 'SSL2', 'SSL3', 'SSL23', 'TLS', 'TLS1', 'TLS1.1', 'TLS1.2']])
    end

    # These are unused but remain for historical reasons
    class << self
      alias builtin_chost CHOST
      alias builtin_cport CPORT
      alias builtin_lhost LHOST
      alias builtin_lport LPORT
      alias builtin_proxies Proxies
      alias builtin_rhost RHOST
      alias builtin_rport RPORT
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
