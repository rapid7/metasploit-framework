# -*- coding: binary -*-
require 'rex/proto/llmnr'
require 'msf/core/exploit'
module Msf

###
#
# This module provides methods for working with LLMNR
#
###
module Auxiliary::LLMNR

  include Auxiliary::Scanner

  #
  # Initializes an instance of an auxiliary module that uses LLMNR
  #

  def initialize(info = {})
    super
    register_options(
    [
      Opt::RHOSTS('224.0.0.252'),
      Opt::RPORT(5355)
    ], self.class)
  end
end
end
