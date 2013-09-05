##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/meterpreter_python'
require 'msf/base/sessions/meterpreter_options'


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
    file = File.join(Msf::Config.data_directory, "meterpreter", "meterpreter.py")

    met = File.open(file, "rb") {|f|
      f.read(f.stat.size)
    }
    met
  end
end
