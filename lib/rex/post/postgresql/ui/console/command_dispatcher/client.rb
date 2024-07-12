# -*- coding: binary -*-

require 'rex/post/sql/ui/console/command_dispatcher/client'

module Rex
  module Post
    module PostgreSQL
      module Ui

        ###
        #
        # Core PostgreSQL client commands
        #
        ###
        class Console::CommandDispatcher::Client
          include Rex::Post::Sql::Ui::Console::CommandDispatcher::Client
          include Rex::Post::PostgreSQL::Ui::Console::CommandDispatcher

          # @return [String]
          def name
            'PostgreSQL Client'
          end

          # @return [Object]
          def cmd_query_help
            print_line 'Usage: query'
            print_line
            print_line 'Run a single SQL query on the target.'
            print_line @@query_opts.usage
            print_line 'Examples:'
            print_line
            print_line '    query SELECT user;'
            print_line '    query SELECT version();'
            print_line '    query SELECT * FROM pg_catalog.pg_tables;'
            print_line
          end

          # @param [Msf::Db::PostgresPR::Connection] result The PostgreSQL query result
          # @return [Hash] Hash containing rows, columns and errors.
          def normalise_sql_result(result)
            # PostgreSQL errors are handled by raising an exception when querying,
            # meaning we don't have that in the Result object.
            { rows: result.rows, columns: result.fields.each.map(&:name), errors: [] }
          end
        end
      end
    end
  end
end
