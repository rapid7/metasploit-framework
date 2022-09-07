# -*- coding => binary -*-

#
# This module provides datastore option definitions and helper methods for payload modules that support UUIDs
#
module Msf::Payload::Custom::Options

  def initialize(info = {})
    super
    register_options(
      [
        Msf::OptPath.new('SHELLCODE_FILE', [false, 'Shellcode bin to launch', nil])
      ], self.class)
  end
end