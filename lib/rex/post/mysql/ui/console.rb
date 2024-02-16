# -*- coding: binary -*-

module Rex
  module Post
    module MySQL
      module Ui

        # This class provides a shell driven interface to the MySQL client API.
        class Console
          include Rex::Ui::Text::DispatcherShell

          # Dispatchers
          require 'rex/post/mysql/ui/console/command_dispatcher'
          require 'rex/post/mysql/ui/console/command_dispatcher/core'
          require 'rex/post/mysql/ui/console/command_dispatcher/client'
          require 'rex/post/mysql/ui/console/command_dispatcher/modules'


          # Initialize the MySQL console.
          #
          # @param [Msf::Sessions::MySQL] session
          def initialize(session)
            # The mysql client context
            self.session = session
            self.client = session.client
            self.client.socket ||= self.client.io
            prompt = "%undMySQL @ #{client.socket.peerinfo} (#{database_name})%clr"
            history_manager = Msf::Config.mysql_session_history
            super(prompt, '>', history_manager, nil, :mysql)

            # Queued commands array
            self.commands = []

            # Point the input/output handles elsewhere
            reset_ui

            enstack_dispatcher(::Rex::Post::MySQL::Ui::Console::CommandDispatcher::Core)
            enstack_dispatcher(::Rex::Post::MySQL::Ui::Console::CommandDispatcher::Client)
            enstack_dispatcher(::Rex::Post::MySQL::Ui::Console::CommandDispatcher::Modules)

            # Set up logging to whatever logsink 'core' is using
            if ! $dispatcher['mysql']
              $dispatcher['mysql'] = $dispatcher['core']
            end
          end

          # Called when someone wants to interact with the mysql client.  It's
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

          # Queues a command to be run when the interactive loop is entered.
          #
          # @param [Object] cmd
          # @return [Object]
          def queue_cmd(cmd)
            self.commands << cmd
          end

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

          # Logs that an error occurred and persists the callstack.
          #
          # @param [Object] msg
          # @return [Object]
          def log_error(msg)
            print_error(msg)

            elog(msg, 'mysql')

            dlog("Call stack:\n#{$@.join("\n")}", 'mysql')
          end

          # @return [Msf::Sessions::MySQL]
          attr_reader :session

          # @return [MySQL::Client]
          attr_reader :client

          # @return [String]
          def database_name
            client.database
          end

          # @param [Object] val
          # @return [String]
          def format_prompt(val)
            prompt = "%undMySQL @ #{client.socket.peerinfo} (#{database_name})%clr > "
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
