# -*- coding: binary -*-

#
# Common command execution implementation for Windows.
#
module Msf
  ###
  #
  # Common command execution implementation for Windows.
  #
  ###
  module Payload::Windows::Exec
    include Msf::Payload::Windows
    include Msf::Payload::Single
    include Msf::Payload::Cmd::Options

    def cmd_required?
      true
    end

    def generate(_opts = {})
      raw = super
      raw = ''.dup if raw.nil?
      raw + command_string + "\x00"
    end

    #
    # Returns the command string to use for execution.
    #
    def command_string
      cmd = datastore['CMD'].to_s

      if cmd.empty? && cmd_required?
        fail_with(Msf::Module::Failure::BadConfig, 'CMD must not be empty')
      end

      cmd
    end
  end
end
