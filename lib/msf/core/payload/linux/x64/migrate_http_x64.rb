# -*- coding: binary -*-

module Msf

###
#
# Payload that supports migration over HTTP/S transports on x86.
#
###

module Payload::Linux::MigrateHttp_x64

  include Msf::Payload::Windows::MigrateCommon

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'HTTP/S Transport Migration (x86)',
      'Description' => 'Migration stub to use over HTTP/S transports via x86',
      'Author'      => ['OJ Reeves'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'linux',
      'Arch'        => ARCH_X64
    ))
  end

  #
  # Constructs the migrate stub on the fly
  #
  def generate_migrate(opts={})
    # This payload only requires the common features, so return
    # an empty string indicating no code requires.
    ''
  end

end

end
