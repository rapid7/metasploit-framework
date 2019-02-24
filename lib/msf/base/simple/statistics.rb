# -*- coding: binary -*-
module Msf
module Simple

###
#
# This class provides an interface to various statistics about the
# framework instance.
#
###
class Statistics
  include Msf::Framework::Offspring

  #
  # Initializes the framework statistics.
  #
  def initialize(framework)
    self.framework = framework
  end

  #
  # Returns the number of encoders in the framework.
  #
  def num_encoders
    framework.encoders.length
  end

  #
  # Returns the number of exploits in the framework.
  #
  def num_exploits
    framework.exploits.length
  end

  #
  # Returns the number of NOP generators in the framework.
  #
  def num_nops
    framework.nops.length
  end

  #
  # Returns the number of payloads in the framework.
  #
  def num_payloads
    framework.payloads.length
  end

  #
  # Returns the number of auxiliary modules in the framework.
  #
  def num_auxiliary
    framework.auxiliary.length
  end

  #
  # Returns the number of post modules in the framework.
  #
  def num_post
    framework.post.length
  end

  def num_evasion
    framework.evasion.length
  end

  #
  # Returns the number of stages in the framework.
  #
  def num_payload_stages
    framework.payloads.stages.length
  end

  #
  # Returns the number of stagers in the framework.
  #
  def num_payload_stagers
    framework.payloads.stagers.length
  end

  #
  # Returns the number of singles in the framework.
  #
  def num_payload_singles
    framework.payloads.singles.length
  end
end

end
end
