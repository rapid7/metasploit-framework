# -*- coding: binary -*-

module Rex
  module Post
    module PostgreSQL
      module Ui

        ###
        #
        # Core PostgreSQL client commands
        #
        ###
        class Console::CommandDispatcher::Core

          include Rex::Post::PostgreSQL::Ui::Console::CommandDispatcher

          #
          # List of supported commands.
          #
          def commands
            cmds = {
              '?'                        => 'Help menu',
              'background'               => 'Backgrounds the current session',
              'bg'                       => 'Alias for background',
              'exit'                     => 'Terminate the PostgreSQL session',
              'help'                     => 'Help menu',
              'irb'                      => 'Open an interactive Ruby shell on the current session',
              'pry'                      => 'Open the Pry debugger on the current session',
              'sessions'                 => 'Quickly switch to another session',
            }

            reqs = {}

            filter_commands(cmds, reqs)
          end

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
