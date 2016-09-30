# -*- coding: binary -*-
require 'msf/core'

###
#
# Base mixin interface for use by single payloads.  Single
# payloads are differentiated from stagers and stages by the
# fact that they run as part of the first stage and have
# no subsequent stages.
#
###
module Msf::Payload::Single

  #
  # Sets the payload type to that of a single payload.
  #
  def payload_type
    return Msf::Payload::Type::Single
  end

  #
  # Conditional generation depending on whether or not this single payload is
  # used in conjunction with a stager.  When a stager is used, generate will
  # return the stager.  When a stager is not used, generate will return the
  # single payload
  #
  def generate
    # If we're staged, then we call the super to generate the STAGER
    if staged?
      super
    # Otherwise, we'll be generating the stage, let's do that now
    else
      # If they defined a custom method that will return the payload, then
      # call it
      if self.class.method_defined?(:generate_stage)
        generate_stage
      # Otherwise, just use the default method to generate the single
      # payload
      else
        super
      end
    end
  end

end
