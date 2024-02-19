# -*- coding: binary -*-

module Rex
  module Post
    module MSSQL
      module Ui
        ###
        #
        # This class provides a shell driven interface to the MSSQL client API.
        #
        ###
        class Console
          include Rex::Ui::Text::DispatcherShell

          # Dispatchers
          require 'rex/post/mssql/ui/console/command_dispatcher'
          require 'rex/post/mssql/ui/console/command_dispatcher/core'
          require 'rex/post/mssql/ui/console/command_dispatcher/client'
          require 'rex/post/mssql/ui/console/command_dispatcher/modules'

          #
          # Initialize the MSSQL console.
          #
          # @param [Msf::Sessions::MSSQL] session
          def initialize(session, opts={})
            # The mssql client context
            self.session = session
            self.client = session.client
            envchange = ::Rex::Proto::MSSQL::ClientMixin::ENVCHANGE
            prompt = "%undMSSQL @ #{client.sock.peerinfo} (#{client.initial_info_for_envchange(envchange: envchange::DATABASE)[:new]})%clr"
            history_manager = Msf::Config.mssql_session_history
            super(prompt, '>', history_manager, nil, :mssql)

            # Queued commands array
            self.commands = []

            # Point the input/output handles elsewhere
            reset_ui

            enstack_dispatcher(::Rex::Post::MSSQL::Ui::Console::CommandDispatcher::Core)
            enstack_dispatcher(::Rex::Post::MSSQL::Ui::Console::CommandDispatcher::Client)
            enstack_dispatcher(::Rex::Post::MSSQL::Ui::Console::CommandDispatcher::Modules)

            # Set up logging to whatever logsink 'core' is using
            if ! $dispatcher['mssql']
              $dispatcher['mssql'] = $dispatcher['core']
            end
          end

          #
          # Called when someone wants to interact with the mssql client.  It's
          # assumed that init_ui has been called prior.
          #
          # @param [Proc] block
          # @return [Integer]
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
          # @param [Object] cmd
          # @return [Object]
          def queue_cmd(cmd)
            self.commands << cmd
          end

          #
          # Runs the specified command wrapper in something to catch meterpreter
          # exceptions.
          #
          # @param [Object] dispatcher
          # @param [Object] method
          # @param [Object] arguments
          # @return [FalseClass]
          def run_command(dispatcher, method, arguments)
            begin
              super
            rescue ::Timeout::Error
              log_error('Operation timed out.')
            rescue ::Rex::InvalidDestination => e
              log_error(e.message)
            rescue ::Errno::EPIPE, ::OpenSSL::SSL::SSLError, ::IOError
              self.session.kill
            rescue ::StandardError => e
              log_error("Error running command #{method}: #{e.class} #{e}")
              elog(e)
            end
          end

          #
          # Logs that an error occurred and persists the callstack.
          #
          # @param [Object] msg
          # @return [Object]
          def log_error(msg)
            print_error(msg)

            elog(msg, 'MSSQL')

            dlog("Call stack:\n#{$@.join("\n")}", 'mssql')
          end

          # @return [Msf::Sessions::MSSQL]
          attr_reader :session

          # @return [MSSQL::Client]
          attr_reader :client

          # @return [String]
          def database_name
            session.client.mssql_query('SELECT DB_NAME();')[:rows][0][0]
          end

          # @param [Object] val
          # @return [String]
          def format_prompt(val)
            prompt = "%undMSSQL @ #{client.sock.peerinfo} (#{database_name})%clr > "
            substitute_colors(prompt, true)
          end

          protected

          attr_writer :session, :client # :nodoc:
          attr_accessor :commands # :nodoc:
        end
      end
    end
  end
end
