# -*- coding => binary -*-

#
# Common command execution helper methods for payloads.
#
module Msf::Payload::Cmd
  #
  # Returns the command string to use for execution
  #
  def command_string
    cmd = datastore['CMD'].to_s

    if cmd.empty? && cmd_required?
      fail_with(Msf::Module::Failure::BadConfig, 'CMD must not be empty')
    end

    cmd
  end

  #
  # Whether CMD is required for the payload
  #
  def cmd_required?
    true
  end
end
