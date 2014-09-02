# -*- coding: binary -*-
require 'rex/proto/ntp'

module Msf

###
#
# This module provides methods for working with NTP
#
###
module Auxiliary::NTP

  include Auxiliary::Scanner

  #
  # Initializes an instance of an auxiliary module that uses NTP
  #

  def initialize(info = {})
    super
    register_options(
    [
      Opt::RPORT(123),
    ], self.class)

    register_advanced_options(
      [
        OptInt.new('VERSION', [true, 'Use this NTP version', 2]),
        OptInt.new('IMPLEMENTATION', [true, 'Use this NTP mode 7 implementation', 3])
      ], self.class)
  end
end
end
