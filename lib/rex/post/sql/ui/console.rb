require 'rex/post/sql/ui/console/command_dispatcher'
require 'rex/post/sql/ui/console/interactive_sql_client'
require 'rex/post/session_compatible_modules'

module Rex
  module Post
    module Sql
      module Ui

        #
        # Base console class for Generic SQL consoles
        #
        module Console

          include Rex::Ui::Text::DispatcherShell
          include Rex::Post::SessionCompatibleModules

          # Called when someone wants to interact with an SQL client.  It's
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

          # @param [Hash] opts
          # @return [String]
          def help_to_s(opts = {})
            super + format_session_compatible_modules
          end

          #
          # Notification to display when initially interacting with the client via the query_interactive command
          #
          # @return [String]
          def interact_with_client_notification
            print_status("Starting interactive SQL shell for #{sql_prompt}")
            print_status('SQL commands ending with ; will be executed on the remote server. Use the %grnexit%clr command to exit.')
            print_line
          end

          #
          # Create prompt via client and session data
          #
          # @return [String]
          def sql_prompt
            "#{session.type} @ #{client.peerinfo} (#{current_database})"
          end

          #
          # Interacts with the supplied client.
          #
          def interact_with_client(client_dispatcher: nil)
            return unless client_dispatcher

            interact_with_client_notification
            client.extend(InteractiveSqlClient) unless client.is_a?(InteractiveSqlClient)
            client.on_command_proc = self.on_command_proc if self.on_command_proc && client.respond_to?(:on_command_proc)
            client.on_print_proc   = self.on_print_proc if self.on_print_proc && client.respond_to?(:on_print_proc)
            client.on_log_proc = method(:log_output) if self.respond_to?(:log_output, true) && client.respond_to?(:on_log_proc)
            client.client_dispatcher = client_dispatcher

            client.interact(input, output)
            client.reset_ui
          end

          # @param [Object] val
          # @return [String]
          def format_prompt(val)
            substitute_colors("%und#{sql_prompt}%clr > ", true)
          end

          #
          # Log that an error occurred.
          #
          def log_error(msg)
            print_error(msg)

            elog(msg, session.type)

            dlog("Call stack:\n#{$ERROR_POSITION.join("\n")}", session.type)
          end

          def current_database
            client.current_database
          end
        end
      end
    end
  end
end
