# -*- coding: binary -*-

require 'English'
require 'rex/post/session_compatible_modules'

module Rex
  module Post
    module SMB
      module Ui
        ###
        #
        # This class provides a shell driven interface to the RubySMB client API.
        #
        ###
        class Console

          include Rex::Ui::Text::DispatcherShell
          include Rex::Post::SessionCompatibleModules

          # Dispatchers
          require 'rex/post/smb/ui/console/command_dispatcher'
          require 'rex/post/smb/ui/console/command_dispatcher/core'
          require 'rex/post/smb/ui/console/command_dispatcher/shares'

          #
          # Initialize the SMB console.
          #
          # @param [Msf::Sessions::SMB] session
          def initialize(session)
            if Rex::Compat.is_windows
              super('smb')
            else
              super('%undSMB%clr', '>', Msf::Config.smb_session_history, nil, :smb)
            end

            # The ruby smb client context
            self.session = session
            self.client = session.client

            # Queued commands array
            self.commands = []

            # Point the input/output handles elsewhere
            reset_ui

            enstack_dispatcher(Rex::Post::SMB::Ui::Console::CommandDispatcher::Core)
            enstack_dispatcher(Rex::Post::SMB::Ui::Console::CommandDispatcher::Shares)

            # Set up logging to whatever logsink 'core' is using
            if !$dispatcher['smb']
              $dispatcher['smb'] = $dispatcher['core']
            end
          end

          #
          # Called when someone wants to interact with the smb client.  It's
          # assumed that init_ui has been called prior.
          #
          def interact(&block)
            # Run queued commands
            commands.delete_if do |ent|
              run_single(ent)
              true
            end

            # Run the interactive loop
            run do |line|
              # Run the command
              run_single(line)

              # If a block was supplied, call it, otherwise return false
              if block
                block.call
              else
                false
              end
            end
          end

          #
          # Queues a command to be run when the interactive loop is entered.
          #
          def queue_cmd(cmd)
            commands << cmd
          end

          #
          # Runs the specified command wrapper in something to catch meterpreter
          # exceptions.
          #
          def run_command(dispatcher, method, arguments)
            super
          rescue Timeout::Error
            log_error('Operation timed out.')
          rescue Rex::InvalidDestination => e
            log_error(e.message)
          rescue ::Errno::EPIPE, ::OpenSSL::SSL::SSLError, ::IOError
            session.kill
          rescue ::StandardError => e
            log_error("Error running command #{method}: #{e.class} #{e}")
            elog(e)
          end

          # @param [Hash] opts
          # @return [String]
          def help_to_s(opts = {})
            super + format_session_compatible_modules
          end

          #
          # Logs that an error occurred and persists the callstack.
          #
          def log_error(msg)
            print_error(msg)

            elog(msg, 'smb')

            dlog("Call stack:\n#{$ERROR_POSITION.join("\n")}", 'smb')
          end

          # @return [Msf::Sessions::SMB]
          attr_reader :session

          # @return [RubySMB::Client]
          attr_reader :client # :nodoc:

          # @return [RubySMB::SMB2::Tree]
          attr_accessor :active_share

          # @return [String]
          attr_accessor :cwd

          def format_prompt(val)
            if active_share
              share_name = active_share.share[/[^\\].*$/, 0]
              cwd = self.cwd.blank? ? '' : "\\#{self.cwd}"
              prompt = "#{share_name}#{cwd}"
            else
              prompt = session.address.to_s
            end

            substitute_colors("%undSMB%clr (#{prompt}) > ", true)
          end

          protected

          attr_writer :session, :client # :nodoc: # :nodoc:
          attr_accessor :commands # :nodoc:

        end
      end
    end
  end
end
