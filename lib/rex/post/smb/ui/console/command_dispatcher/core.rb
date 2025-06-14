# -*- coding: binary -*-

require 'rex/post/smb'

module Rex
  module Post
    module SMB
      module Ui
        ###
        #
        # Core SMB client commands
        #
        ###
        class Console::CommandDispatcher::Core

          include Rex::Post::SMB::Ui::Console::CommandDispatcher

          #
          # Initializes an instance of the core command set using the supplied session and client
          # for interactivity.
          #
          # @param [Rex::Post::SMB::Ui::Console] console

          #
          # List of supported commands.
          #
          def commands
            cmds = {
              '?' => 'Help menu',
              'background' => 'Backgrounds the current session',
              'bg' => 'Alias for background',
              'exit' => 'Terminate the SMB session',
              'help' => 'Help menu',
              'irb' => 'Open an interactive Ruby shell on the current session',
              'pry' => 'Open the Pry debugger on the current session',
              'sessions' => 'Quickly switch to another session'
            }

            reqs = {}

            filter_commands(cmds, reqs)
          end

          #
          # Core
          #
          def name
            'Core'
          end

          def unknown_command(cmd, line)
            status = super

            status
          end

        end
      end
    end
  end
end
