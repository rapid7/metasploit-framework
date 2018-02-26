# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows/x64/block_api'

module Msf

###
#
# Payload that supports migration over HTTP/S transports on x64.
#
###

module Payload::Windows::MigrateHttp_x64

  include Msf::Payload::Windows::MigrateCommon_x64

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'HTTP/S Transport Migration (x64)',
      'Description' => 'Migration stub to use over HTTP/S transports via x64',
      'Author'      => ['OJ Reeves'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
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

