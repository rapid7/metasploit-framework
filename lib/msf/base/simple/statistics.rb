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
    Msf::Modules::Metadata::Cache.instance.update_stats
  end

  #
  # Returns the number of encoders in the framework.
  #
  def num_encoders
    Msf::Modules::Metadata::Cache.instance.module_counts[:encoder]
  end

  #
  # Returns the number of exploits in the framework.
  #
  def num_exploits
    Msf::Modules::Metadata::Cache.instance.module_counts[:exploit]
  end

  #
  # Returns the number of NOP generators in the framework.
  #
  def num_nops
    Msf::Modules::Metadata::Cache.instance.module_counts[:nop]
  end

  #
  # Returns the number of payloads in the framework.
  #
  def num_payloads
    Msf::Modules::Metadata::Cache.instance.module_counts[:payload]
  end

  #
  # Returns the number of auxiliary modules in the framework.
  #
  def num_auxiliary
    Msf::Modules::Metadata::Cache.instance.module_counts[:auxiliary]
  end

  #
  # Returns the number of post modules in the framework.
  #
  def num_post
    Msf::Modules::Metadata::Cache.instance.module_counts[:post]
  end

  def num_evasion
    Msf::Modules::Metadata::Cache.instance.module_counts[:evasion]
  end
end

end
end
