# -*- coding: binary -*-

require 'rex/ui/text/dispatcher_shell'

module Rex
  module Post
    module MSSQL
      module Ui
        ###
        #
        # Base class for all command dispatchers within the MSSQL console user interface.
        #
        ###
        module Console::CommandDispatcher
          include Msf::Ui::Console::CommandDispatcher::Session

          #
          # Initializes an instance of the core command set using the supplied session and client
          # for interactivity.
          #
          # @param [Rex::Post::MSSQL::Ui::Console] console
          def initialize(console)
            super
            @msf_loaded = nil
            @filtered_commands = []
          end

          #
          # Returns the MSSQL client context.
          #
          # @return [MSSQL::Client]
          def client
            console = shell
            console.client
          end

          #
          # Returns the MSSQL session context.
          #
          # @return [Msf::Sessions::MSSQL]
          def session
            console = shell
            console.session
          end

          #
          # Returns the commands that meet the requirements
          #
          # @param [Object] all
          # @param [Object] reqs
          # @return [Object]
          def filter_commands(all, reqs)
            all.delete_if do |cmd, _desc|
              if reqs[cmd]&.any? { |req| !client.commands.include?(req) }
                @filtered_commands << cmd
                true
              end
            end
          end

          # @param [Object] cmd
          # @param [Object] line
          # @return [Symbol, nil]
          def unknown_command(cmd, line)
            if @filtered_commands.include?(cmd)
              print_error("The \"#{cmd}\" command is not supported by this session type (#{session.session_type})")
              return :handled
            end

            super
          end

          #
          # Return the subdir of the `documentation/` directory that should be used
          # to find usage documentation
          #
          # @return [String]
          def docs_dir
            ::File.join(super, 'mssql_session')
          end

          #
          # Returns true if the client has a framework object.
          #
          # Used for firing framework session events
          #
          # @return [TrueClass, FalseClass]
          def msf_loaded?
            return @msf_loaded unless @msf_loaded.nil?

            # if we get here we must not have initialized yet

            @msf_loaded = !session.framework.nil?
            @msf_loaded
          end

          #
          # Log that an error occurred.
          #
          # @param [Object] msg
          # @return [Object]
          def log_error(msg)
            print_error(msg)

            elog(msg, 'mssql')

            dlog("Call stack:\n#{$ERROR_POSITION.join("\n")}", 'mssql')
          end
        end
      end
    end
  end
end
