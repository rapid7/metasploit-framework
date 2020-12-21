# -*- coding: binary -*-
require 'msf/core'

###
# This class is here to implement advanced features for hardware bridged
# payloads. HWBridge payloads are expected to include this module if
# they want to support these features.
###
module Msf::Payload::Hardware
  def initialize(info = {})
    super(info)
  end

  ##
  # Returns a list of compatible encoders based on mainframe architecture
  # most will not work because of the different architecture
  # an XOR-based encoder will be defined soon
  ##
  def compatible_encoders
    encoders2 = ['/generic\/none/', 'none']
    encoders2
  end

end
