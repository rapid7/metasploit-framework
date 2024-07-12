# -*- coding: binary -*-

require 'rex/post/sql/ui/console/command_dispatcher/client'
require 'rex/post/sql/ui/console/command_dispatcher/core'

module Rex
  module Post
    module Sql
      module Ui
        module Console

          ###
          #
          # Base class for all command dispatchers within the Generic SQL console user interface.
          #
          ###
          module CommandDispatcher

            include Msf::Ui::Console::CommandDispatcher::Session

            #
            # Initializes an instance of the core command set using the supplied session and client
            # for interactivity.
            #
            # @param [Rex::Post::PostgreSQL::Ui::Console] console
            def initialize(console)
              super
              @msf_loaded = nil
              @filtered_commands = []
            end

            #
            # Returns the SQL client context.
            # @return [Object]
            def client
              console = shell
              console.client
            end

            #
            # Returns the PostgreSQL session context.
            #
            # @return [Msf::Sessions::PostgreSQL]
            def session
              console = shell
              console.session
            end

            #
            # Returns the commands that meet the requirements
            #
            def filter_commands(all, reqs)
              all.delete_if do |cmd, _desc|
                if reqs[cmd]&.any? { |req| !client.commands.include?(req) }
                  @filtered_commands << cmd
                  true
                end
              end
            end

            def unknown_command(cmd, line)
              if @filtered_commands.include?(cmd)
                print_error("The \"#{cmd}\" command is not supported by this session type (#{session.session_type})")
                return :handled
              end

              super
            end

            #
            # Returns true if the client has a framework object.
            #
            # Used for firing framework session events
            #
            def msf_loaded?
              return @msf_loaded unless @msf_loaded.nil?

              # if we get here we must not have initialized yet

              @msf_loaded = !session.framework.nil?
              @msf_loaded
            end
          end
        end
      end
    end
  end
end
