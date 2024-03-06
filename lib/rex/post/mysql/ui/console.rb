# -*- coding: binary -*-

require 'rex/post/sql/ui/console'

module Rex
  module Post
    module MySQL
      module Ui

        # This class provides a shell driven interface to the MySQL client API.
        class Console
          include Rex::Post::Sql::Ui::Console
          include Rex::Ui::Text::DispatcherShell

          # Dispatchers
          require 'rex/post/mysql/ui/console/command_dispatcher'
          require 'rex/post/mysql/ui/console/command_dispatcher/core'
          require 'rex/post/mysql/ui/console/command_dispatcher/client'

          # Initialize the MySQL console.
          #
          # @param [Msf::Sessions::MySQL] session
          def initialize(session)
            # The mysql client context
            self.session = session
            self.client = session.client
            self.client.socket ||= self.client.io
            prompt = "%undMySQL @ #{client.socket.peerinfo} (#{current_database})%clr"
            history_manager = Msf::Config.mysql_session_history
            super(prompt, '>', history_manager, nil, :mysql)

            # Queued commands array
            self.commands = []

            # Point the input/output handles elsewhere
            reset_ui

            enstack_dispatcher(::Rex::Post::MySQL::Ui::Console::CommandDispatcher::Core)
            enstack_dispatcher(::Rex::Post::MySQL::Ui::Console::CommandDispatcher::Client)
            enstack_dispatcher(Msf::Ui::Console::CommandDispatcher::LocalFileSystem)

            # Set up logging to whatever logsink 'core' is using
            if ! $dispatcher['mysql']
              $dispatcher['mysql'] = $dispatcher['core']
            end
          end

          # @return [Msf::Sessions::MySQL]
          attr_reader :session

          # @return [MySQL::Client]
          attr_reader :client

          protected

          attr_writer :session, :client # :nodoc:
          attr_accessor :commands # :nodoc:
        end
      end
    end
  end
end
