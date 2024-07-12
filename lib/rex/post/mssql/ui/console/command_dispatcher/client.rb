# -*- coding: binary -*-

require 'rex/post/sql/ui/console/command_dispatcher/client'

module Rex
  module Post
    module MSSQL
      module Ui
        ###
        #
        # Core MSSQL client commands
        #
        ###
        class Console::CommandDispatcher::Client
          include Rex::Post::Sql::Ui::Console::CommandDispatcher::Client
          include Rex::Post::MSSQL::Ui::Console::CommandDispatcher

          # @return [String]
          def name
            'MSSQL Client'
          end

          # @return [Object]
          def cmd_query_help
            print_line 'Usage: query'
            print_line
            print_line 'Run a single SQL query on the target.'
            print_line @@query_opts.usage
            print_line 'Examples:'
            print_line
            print_line '    query select @@version;'
            print_line '    query select user_name();'
            print_line '    query select name from master.dbo.sysdatabases;'
            print_line
          end

          # @param [Hash] result The MSSQL query result
          # @return [Hash] Hash containing rows, columns and errors.
          def normalise_sql_result(result)
            { rows: result[:rows], columns: result[:colnames], errors: result[:errors] }
          end
        end
      end
    end
  end
end
