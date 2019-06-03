# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows/migrate_common'

module Msf

###
#
# Payload that supports migration over HTTP/S transports on x86.
#
###

module Payload::Windows::MigrateHttp

  include Msf::Payload::Windows::MigrateCommon

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'HTTP/S Transport Migration (x86)',
      'Description' => 'Migration stub to use over HTTP/S transports via x86',
      'Author'      => ['OJ Reeves'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X86
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
