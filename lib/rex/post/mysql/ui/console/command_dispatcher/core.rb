# -*- coding: binary -*-

module Rex
  module Post
    module MySQL
      module Ui

        # Core MySQL client commands
        class Console::CommandDispatcher::Core

          include Rex::Post::MySQL::Ui::Console::CommandDispatcher

          # List of supported commands.
          #
          # @return [Hash{String->String}]
          def commands
            cmds = {
              '?'                        => 'Help menu',
              'background'               => 'Backgrounds the current session',
              'bg'                       => 'Alias for background',
              'exit'                     => 'Terminate the MySQL session',
              'help'                     => 'Help menu',
              'irb'                      => 'Open an interactive Ruby shell on the current session',
              'pry'                      => 'Open the Pry debugger on the current session',
              'sessions'                 => 'Quickly switch to another session',
            }

            reqs = {}

            filter_commands(cmds, reqs)
          end

          # @return [String]
          def name
            'Core'
          end

          # @param [Object] cmd
          # @param [Object] line
          # @return [Symbol, nil]
          def unknown_command(cmd, line)
            status = super

            status
          end
        end
      end
    end
  end
end
