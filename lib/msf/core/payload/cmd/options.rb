# -*- coding => binary -*-

#
# This module provides datastore option definitions
# for payload modules that support command execution.
#

#
# Common datastore option definitions for command execution payloads.
#
module Msf::Payload::Cmd::Options
  def initialize(info = {})
    super

    register_options(
      [
        Msf::OptString.new(
          'CMD',
          [ cmd_required?, 'The command string to execute' ]
        )
      ],
      self.class
    )
  end
end
