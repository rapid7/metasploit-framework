# -*- coding: binary -*-

require 'rex/post/sql/ui/console'

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
          include Rex::Post::Sql::Ui::Console
          include Rex::Ui::Text::DispatcherShell

          # Dispatchers
          require 'rex/post/postgresql/ui/console/command_dispatcher'
          require 'rex/post/postgresql/ui/console/command_dispatcher/core'
          require 'rex/post/postgresql/ui/console/command_dispatcher/client'

          #
          # Initialize the PostgreSQL console.
          #
          # @param [Msf::Sessions::PostgreSQL] session
          def initialize(session)
            # The postgresql client context
            self.session = session
            self.client = session.client
            prompt = "%undPostgreSQL @ #{client.conn.peerinfo} (#{current_database})%clr"
            history_manager = Msf::Config.postgresql_session_history
            super(prompt, '>', history_manager, nil, :postgresql)

            # Queued commands array
            self.commands = []

            # Point the input/output handles elsewhere
            reset_ui

            enstack_dispatcher(::Rex::Post::PostgreSQL::Ui::Console::CommandDispatcher::Core)
            enstack_dispatcher(::Rex::Post::PostgreSQL::Ui::Console::CommandDispatcher::Client)
            enstack_dispatcher(Msf::Ui::Console::CommandDispatcher::LocalFileSystem)

            # Set up logging to whatever logsink 'core' is using
            if ! $dispatcher['postgresql']
              $dispatcher['postgresql'] = $dispatcher['core']
            end
          end

          # @return [Msf::Sessions::PostgreSQL]
          attr_reader :session

          # @return [PostgreSQL::Client]
          attr_reader :client # :nodoc:

          protected

          attr_writer :session, :client # :nodoc:
          attr_accessor :commands # :nodoc:
        end
      end
    end
  end
end
