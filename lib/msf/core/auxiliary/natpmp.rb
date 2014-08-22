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
        Opt::CHOST
      ],
      self.class
    )
  end
end
end
