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
        OptString.new('VERSIONS', [true, 'Try these NTP versions', '2,3']),
        OptString.new('IMPLEMENTATIONS', [true, 'Try these NTP mode 7 implementations', '3,2'])
      ], self.class)
  end
end
end
