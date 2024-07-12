# -*- coding: binary -*-

require 'rex/post/sql/ui/console/command_dispatcher/core'

module Rex
  module Post
    module MySQL
      module Ui

        # Core MySQL client commands
        class Console::CommandDispatcher::Core
          include Rex::Post::Sql::Ui::Console::CommandDispatcher::Core
          include Rex::Post::MySQL::Ui::Console::CommandDispatcher
        end
      end
    end
  end
end
