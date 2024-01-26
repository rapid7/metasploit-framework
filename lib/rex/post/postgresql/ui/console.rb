# -*- coding: binary -*-

module Rex
  module Post
    module PostgreSQL
      module Ui
        ###
        #
        # This class provides a shell driven interface to the PostgreSQL client API.
        #
        ###
        class Console
          include Rex::Ui::Text::DispatcherShell

          # Dispatchers
          require 'rex/post/postgresql/ui/console/command_dispatcher'
          require 'rex/post/postgresql/ui/console/command_dispatcher/core'
          require 'rex/post/postgresql/ui/console/command_dispatcher/client'
          require 'rex/post/postgresql/ui/console/command_dispatcher/modules'

          #
          # Initialize the PostgreSQL console.
          #
          # @param [Msf::Sessions::PostgreSQL] session
          def initialize(session)
            # The postgresql client context
            self.session = session
            self.client = session.client
            self.cwd = client.params['database']
            prompt = "%undPostgreSQL @ #{client.conn.peerinfo} (#{cwd})%clr"
            history_manager = Msf::Config.postgresql_session_history
            super(prompt, '>', history_manager, nil, :postgresql)

            # Queued commands array
            self.commands = []

            # Point the input/output handles elsewhere
            reset_ui

            enstack_dispatcher(::Rex::Post::PostgreSQL::Ui::Console::CommandDispatcher::Core)
            enstack_dispatcher(::Rex::Post::PostgreSQL::Ui::Console::CommandDispatcher::Client)
            enstack_dispatcher(::Rex::Post::PostgreSQL::Ui::Console::CommandDispatcher::Modules)

            # Set up logging to whatever logsink 'core' is using
            if ! $dispatcher['postgresql']
              $dispatcher['postgresql'] = $dispatcher['core']
            end
          end

          #
          # Called when someone wants to interact with the postgresql client.  It's
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
            self.commands << cmd
          end

          #
          # Runs the specified command wrapper in something to catch meterpreter
          # exceptions.
          #
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
          def log_error(msg)
            print_error(msg)

            elog(msg, 'postgresql')

            dlog("Call stack:\n#{$@.join("\n")}", 'postgresql')
          end

          # @return [Msf::Sessions::PostgreSQL]
          attr_reader :session

          # @return [PostgreSQL::Client]
          attr_reader :client # :nodoc:

          # @return [String]
          attr_accessor :cwd

          def format_prompt(val)
            cwd ||= client.params['database']
            prompt = "%undPostgreSQL @ #{client.conn.peerinfo} (#{cwd})%clr > "
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
