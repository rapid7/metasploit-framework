# -*- coding: binary -*-
require 'msf/core'

###
#
# This class is here to implement advanced features for mainframe based
# payloads. Mainframe payloads are expected to include this module if
# they want to support these features.
#
###
module Msf::Payload::Mainframe

  #
  # Z notes
  # Z notes
  #
  def initialize(info = {})
    ret = super(info)
  end

  #
  # Returns a list of compatible encoders based on mainframe architecture
  # most will not work because of the different architecture
  # an XOR-based encoder will be defined soon
  #
  def compatible_encoders
    encoders = super()
    encoders2 = ['/generic\/none/','none']

    return encoders2
  end

end
