# -*- coding: binary -*-

#
# A helper module for using and referencing comming user agent strings.
#
module Rex::UserAgent

  #
  # List from https://techblog.willshouse.com/2012/01/03/most-common-user-agents/
  # This article was updated on July 11th 2015. It's probably worth updating this
  # list over time.
  #
  # This list is in the order of most common to least common.
  #
  def self.agents
    @@agents ||= File.binread(File.join(Msf::Config.data_directory, "user_agents.txt")).split("\n")
  end

  #
  # Pick a random agent from the common agent list.
  #
  def self.random
    self.agents.sample
  end

  #
  # Choose the agent with the shortest string (for use in payloads)
  #
  def self.shortest
    @@shortest_agent ||= self.agents.min { |a, b| a.size <=> b.size }
  end

  #
  # Choose the most frequent user agent
  #
  def self.most_common
    self.agents[0]
  end
end

