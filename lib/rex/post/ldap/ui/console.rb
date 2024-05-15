# -*- coding: binary -*-

require 'English'
require 'rex/post/session_compatible_modules'

module Rex
  module Post
    module LDAP
      module Ui
        ###
        #
        # This class provides a shell driven interface to the LDAP client API.
        #
        ###
        class Console

          include Rex::Ui::Text::DispatcherShell
          include Rex::Post::SessionCompatibleModules

          # Dispatchers
          require 'rex/post/ldap/ui/console/command_dispatcher'
          require 'rex/post/ldap/ui/console/command_dispatcher/core'
          require 'rex/post/ldap/ui/console/command_dispatcher/client'

          #
          # Initialize the LDAP console.
          #
          # @param [Msf::Sessions::LDAP] session
          def initialize(session)
            super('%undLDAP%clr', '>', Msf::Config.ldap_session_history, nil, :ldap)

            # The ldap client context
            self.session = session
            self.client = session.client

            # Queued commands array
            self.commands = []

            # Point the input/output handles elsewhere
            reset_ui

            enstack_dispatcher(Rex::Post::LDAP::Ui::Console::CommandDispatcher::Client)
            enstack_dispatcher(Rex::Post::LDAP::Ui::Console::CommandDispatcher::Core)
            enstack_dispatcher(Msf::Ui::Console::CommandDispatcher::LocalFileSystem)

            # Set up logging to whatever logsink 'core' is using
            if !$dispatcher['ldap']
              $dispatcher['ldap'] = $dispatcher['core']
            end
          end

          #
          # Called when someone wants to interact with the LDAP client.  It's
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
          # Runs the specified command wrapper in something to catch exceptions.
          #
          def run_command(dispatcher, method, arguments)
            super
          rescue Timeout::Error
            log_error('Operation timed out.')
          rescue Rex::InvalidDestination => e
            log_error(e.message)
          rescue ::Errno::EPIPE, ::OpenSSL::SSL::SSLError, ::IOError, Net::LDAP::ResponseMissingOrInvalidError
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

            elog(msg, 'ldap')

            dlog("Call stack:\n#{$ERROR_POSITION.join("\n")}", 'ldap')
          end

          # @return [Msf::Sessions::LDAP]
          attr_reader :session

          # @return [Rex::Proto::LDAP::Client]
          attr_reader :client # :nodoc:

          def format_prompt(val)
            prompt = session.address.to_s

            substitute_colors("%undLDAP%clr (#{prompt}) > ", true)
          end

          protected

          attr_writer :session, :client # :nodoc: # :nodoc:
          attr_accessor :commands # :nodoc:
        end
      end
    end
  end
end
