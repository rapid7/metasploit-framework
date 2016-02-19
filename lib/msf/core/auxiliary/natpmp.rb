# -*- coding: binary -*-
require 'rex/proto/natpmp'

module Msf

###
#
# This module provides methods for working with NAT-PMP
#
###
module Auxiliary::NATPMP

  include Auxiliary::Scanner
  include Rex::Proto::NATPMP

  def initialize(info = {})
    super
    register_options(
      [
        Opt::RPORT(Rex::Proto::NATPMP::DefaultPort),
        Opt::CHOST,
        OptInt.new('LIFETIME', [true, "Time in ms to keep this port forwarded (set to 0 to destroy a mapping)", 3600000]),
        OptEnum.new('PROTOCOL', [true, "Protocol to forward", 'TCP', %w(TCP UDP)])
      ],
      self.class
    )
  end

  def lifetime
    @lifetime ||= datastore['LIFETIME']
  end

  def protocol
    @protocol ||= datastore['PROTOCOL']
  end
end
end
