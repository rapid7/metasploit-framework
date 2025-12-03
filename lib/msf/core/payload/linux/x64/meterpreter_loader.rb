# -*- coding: binary -*-


module Msf

###
#
# Common module stub for ARCH_X64 payloads that make use of Meterpreter.
#
###

module Payload::Linux::X64::MeterpreterLoader


  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Meterpreter & Configuration RDI',
      'Description'   => 'Inject Meterpreter & the configuration stub via RDI',
      'Author'        => [ 'sf', 'OJ Reeves' ],
      'Platform'      => 'linux',
      'Arch'          => ARCH_X64,

      ))
  end


  def stage_payload(opts={})
      "\xde\xad\xbe\xef"
  end

  def generate_config(opts={})
    ds = opts[:datastore] || datastore
    opts[:uuid] ||= generate_payload_uuid

    # create the configuration block, which for staged connections is really simple.
    config_opts = {
      arch:              opts[:uuid].arch,
      null_session_guid: opts[:null_session_guid] == true,
      exitfunk:          ds[:exit_func] || ds['EXITFUNC'],
      expiration:        (ds[:expiration] || ds['SessionExpirationTimeout']).to_i,
      uuid:              opts[:uuid],
      transports:        opts[:transport_config] || [transport_config(opts)],
      extensions:        [],
      stageless:         opts[:stageless] == true,
    }.merge(meterpreter_logging_config(opts))
    # create the configuration instance based off the parameters
    config = Rex::Payloads::Meterpreter::Config.new(config_opts)

    # return the binary version of it
    config.to_b
  end

  def stage_meterpreter(opts={})
      "\xde\xad\xbe\xef"
  end

end

end

