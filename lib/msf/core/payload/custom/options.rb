# -*- coding => binary -*-

#
# This module provides datastore option definitions and helper methods for payload modules that support UUIDs
#
module Msf::Payload::Custom::Options

  def initialize(info = {})
    super
    register_options(
      [
        Msf::OptPath.new('SHELLCODE_FILE', [false, "shellcode bin to launch", nil])
      ], self.class)
    register_advanced_options(
      [
        Msf::OptBool.new('PrependSize', [true, "prepend stage size when sending", true])
      ], self.class)
  end
end