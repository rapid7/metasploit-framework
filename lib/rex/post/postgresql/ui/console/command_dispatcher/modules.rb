# -*- coding: binary -*-

require 'rex/post/sql/ui/console/command_dispatcher/modules'

module Rex
  module Post
    module PostgreSQL
      module Ui
        ###
        #
        # PostgreSQL client commands for running modules
        #
        ###
        class Console::CommandDispatcher::Modules
          include Rex::Post::Sql::Ui::Console::CommandDispatcher::Modules
          include Rex::Post::PostgreSQL::Ui::Console::CommandDispatcher

          def cmd_run_help
            print_line 'Usage: run'
            print_line
            print_line 'Run a module or script against the current session.'
            print_line
            print_line '    run auxiliary/scanner/postgres/postgres_schemadump'
            print_line '    run auxiliary/scanner/postgres/postgres_hashdump'
            print_line '    run auxiliary/admin/postgres/postgres_readfile'
            print_line '    run my_erb_script.rc'
            print_line
          end
        end
      end
    end
  end
end
