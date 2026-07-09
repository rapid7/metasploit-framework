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
    ensure_stats_loaded
    Msf::Modules::Metadata::Cache.instance.module_counts[:encoder]
  end

  #
  # Returns the number of exploits in the framework.
  #
  def num_exploits
    ensure_stats_loaded
    Msf::Modules::Metadata::Cache.instance.module_counts[:exploit]
  end

  #
  # Returns the number of NOP generators in the framework.
  #
  def num_nops
    ensure_stats_loaded
    Msf::Modules::Metadata::Cache.instance.module_counts[:nop]
  end

  #
  # Returns the number of payloads in the framework.
  #
  def num_payloads
    ensure_stats_loaded
    Msf::Modules::Metadata::Cache.instance.module_counts[:payload]
  end

  #
  # Returns the number of auxiliary modules in the framework.
  #
  def num_auxiliary
    ensure_stats_loaded
    Msf::Modules::Metadata::Cache.instance.module_counts[:auxiliary]
  end

  #
  # Returns the number of post modules in the framework.
  #
  def num_post
    ensure_stats_loaded
    Msf::Modules::Metadata::Cache.instance.module_counts[:post]
  end

  def num_evasion
    ensure_stats_loaded
    Msf::Modules::Metadata::Cache.instance.module_counts[:evasion]
  end

  private

  # Defers update_stats until first access so boot doesn't pay the cost
  # when stats aren't immediately needed (e.g. quiet mode with no banner).
  def ensure_stats_loaded
    cache = Msf::Modules::Metadata::Cache.instance
    cache.update_stats unless cache.module_counts
  end
end

end
end
