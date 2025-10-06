# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
  module Post
    module Meterpreter
      module Ui
        ###
        #
        # Standard Fs API extension.
        #
        ###
        class Console::CommandDispatcher::Stdapi_Fs

          require 'rex/post/meterpreter/ui/console/command_dispatcher/stdapi'
          require 'rex/post/meterpreter/ui/console/command_dispatcher/stdapi/fs'
          Klass = Console::CommandDispatcher::Stdapi_Fs

          Dispatchers =
            [
              Console::CommandDispatcher::Stdapi::Fs,
            ]

          include Console::CommandDispatcher

          def self.has_command?(name)
            Dispatchers.any? { |klass| klass.has_command?(name) }
          end

          #
          # Initializes an instance of the stdapi command interaction.
          #
          def initialize(shell)
            super

            Dispatchers.each { |d|
              shell.enstack_dispatcher(d)
            }
            str_dispatchers = []
            uniq_dispatchers = []
            idx = 0
            while idx < shell.dispatcher_stack.length
              unless str_dispatchers.include?(shell.dispatcher_stack[idx].class.to_s)
                str_dispatchers.push(shell.dispatcher_stack[idx].class.to_s)
                uniq_dispatchers.push(shell.dispatcher_stack[idx])
              end
              idx += 1
            end
            shell.dispatcher_stack = uniq_dispatchers
          end

          #
          # List of supported commands.
          #
          def commands
            {
            }
          end

          #
          # Name for this dispatcher
          #
          def name
            "Standard FS extension"
          end
        end
      end
    end
  end
end
