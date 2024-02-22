# -*- coding: binary -*-

require 'rex/post/sql/ui/console/command_dispatcher/core'

module Rex
  module Post
    module PostgreSQL
      module Ui

        ###
        #
        # Core PostgreSQL client commands
        #
        ###
        class Console::CommandDispatcher::Core
          include Rex::Post::Sql::Ui::Console::CommandDispatcher::Core
          include Rex::Post::PostgreSQL::Ui::Console::CommandDispatcher
        end
      end
    end
  end
end
