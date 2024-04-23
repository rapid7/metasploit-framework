# -*- coding: binary -*-

require 'rex/post/sql/ui/console/command_dispatcher/client'

module Rex
  module Post
    module MySQL
      module Ui

        # Core MySQL client commands
        class Console::CommandDispatcher::Client
          include Rex::Post::Sql::Ui::Console::CommandDispatcher::Client
          include Rex::Post::MySQL::Ui::Console::CommandDispatcher

          # @return [String]
          def name
            'MySQL Client'
          end

          # @return [Object]
          def cmd_query_help
            print_line 'Usage: query'
            print_line
            print_line 'Run a single SQL query on the target.'
            print_line @@query_opts.usage
            print_line 'Examples:'
            print_line
            print_line '    query SHOW DATABASES;'
            print_line '    query USE information_schema;'
            print_line '    query SELECT * FROM SQL_FUNCTIONS;'
            print_line '    query SELECT version();'
            print_line
          end

          # @param [Mysql::Result] result The MySQL query result
          # @return [Hash] Hash containing rows, columns and errors.
          def normalise_sql_result(result)
            # MySQL errors are handled by raising an exception when querying,
            # meaning we don't have that in the Result object.
            { rows: result.entries, columns: result.fields.each.map(&:name), errors: [] }
          end

          def handle_error(e)
            case e
            when Mysql::ClientError::ServerLost
              _close_session
            end
            super
          end
        end
      end
    end
  end
end
