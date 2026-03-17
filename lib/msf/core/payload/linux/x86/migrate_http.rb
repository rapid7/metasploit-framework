# -*- coding: binary -*-

module Msf

###
#
# Payload that supports migration on x86.
#
###

module Payload::Linux::X86::MigrateHttp

  include Msf::Payload::Linux:X86::Migrate

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'Linux Migration (x86)',
      'Description' => 'Migration stub x86',
      'Author'      => ['OJ Reeves', 'msutovsky-r7'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'linux',
      'Arch'        => ARCH_X86
    ))
  end

  #
  # Constructs the migrate stub on the fly
  #
  def generate_stub(opts={})
    %Q^
      nop
      nop
      nop
    ^
  end

end

end

