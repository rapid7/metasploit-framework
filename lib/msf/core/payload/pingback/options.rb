# -*- coding => binary -*-

require 'msf/core'
require 'msf/core/payload/pingback'

#
# This module provides datastore option definitions and helper methods for payload modules that support UUIDs
#
module Msf::Payload::Pingback::Options

  def initialize(info = {})
    super
    register_advanced_options(
      [
        Msf::OptInt.new('PingbackRetries', [true, "How many additional successful pingbacks", 0]),
        Msf::OptInt.new('PingbackSleep', [true, "Time (in seconds) to sleep between pingbacks", 30]),
        Msf::OptString.new('PingbackUUID', [ false, 'A pingback UUID to use']),
        Msf::OptBool.new('PingbackUUIDDatabase', [ true, 'save the pingback UUID to the database', false]),
      ], self.class)
  end


end
