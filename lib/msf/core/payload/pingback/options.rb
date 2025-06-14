# -*- coding => binary -*-

#
# This module provides datastore option definitions and helper methods for payload modules that support UUIDs
#
module Msf::Payload::Pingback::Options

  def initialize(info = {})
    super
    register_advanced_options(
      [
        Msf::OptInt.new('PingbackRetries', [true, "How many additional successful pingbacks", 0]),
        Msf::OptInt.new('PingbackSleep', [true, "Time (in seconds) to sleep between pingbacks", 30])
      ], self.class)
  end


end
