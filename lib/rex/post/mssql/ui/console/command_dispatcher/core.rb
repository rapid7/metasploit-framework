# -*- coding: binary -*-

require 'rex/post/sql/ui/console/command_dispatcher/core'

module Rex
  module Post
    module MSSQL
      module Ui
        ###
        #
        # Core MSSQL client commands
        #
        ###
        class Console::CommandDispatcher::Core
          include Rex::Post::Sql::Ui::Console::CommandDispatcher::Core
          include Rex::Post::MSSQL::Ui::Console::CommandDispatcher
        end
      end
    end
  end
end
