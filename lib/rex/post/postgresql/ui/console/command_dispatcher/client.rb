# -*- coding: binary -*-

require 'pathname'
require 'reline'

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

          include Rex::Post::PostgreSQL::Ui::Console::CommandDispatcher

          #
          # Initializes an instance of the core command set using the supplied console
          # for interactivity.
          #
          # @param [Rex::Post::PostgreSQL::Ui::Console] console
          def initialize(console)
            super

            @db_search_results = []
          end

          #
          # List of supported commands.
          #
          def commands
            cmds = {
              'query'   => 'Run a raw SQL query',
              'shell'   => 'Enter a raw shell where SQL queries can be executed',
            }

            reqs = {}

            filter_commands(cmds, reqs)
          end

          def name
            'PostgreSQL Client'
          end

          def help_args?(args)
            return false unless args.instance_of?(::Array)

            args.include?('-h') || args.include?('--help')
          end

          def cmd_shell_help
            print_line 'Usage: shell'
            print_line
            print_line 'Go into a raw SQL shell where SQL queries can be executed.'
            print_line 'To exit, type `exit`, `quit`, `end` or `stop`.'
            print_line
          end

          def cmd_shell(*args)
            cmd_shell_help && return if help_args?(args)

            prompt_proc_before = ::Reline.prompt_proc

            ::Reline.prompt_proc = proc { |line_buffer| line_buffer.each_with_index.map { |_line, i| i > 0 ? 'SQL *> ' : 'SQL >> ' } }

            stop_words = %w[stop s exit e end quit q].freeze

            # Allow the user to query the DB in a loop.
            finished = false
            until finished
              begin
                # This will loop until it receives `true`.
                raw_query = ::Reline.readmultiline('SQL >> ', use_history = true) do |multiline_input|
                  finished = stop_words.include?(multiline_input.split.last)
                  # Accept the input until the current line does not end with '\', similar to a shell
                  finished || !multiline_input.split.last.end_with?('\\')
                end
              rescue ::Interrupt
                finished = true
              ensure
                ::Reline.prompt_proc = prompt_proc_before
              end

              if finished
                print_status 'Exiting Shell mode.'
                return
              end

              formatted_query = raw_query.split.map { |word| word.chomp('\\') }.reject(&:empty?).compact.join(' ')

              print_status "Running SQL Command: '#{formatted_query}'"
              cmd_query(formatted_query)
            end
          end

          def cmd_query_help
            print_line 'Usage: query'
            print_line
            print_line 'You can also use `sql`.'
            print_line 'Run a raw SQL query on the target.'
            print_line
          end

          #
          # @param [::Msf::Db::PostgresPR::Connection::Result] result The result of an SQL query to format.
          def format_result(result)
            columns = ['#']
            columns.append(result.fields.map.each { |field| field[:name] })
            flat_columns = columns.flatten

            ::Rex::Text::Table.new(
              'Header' => 'Query',
              'Indent' => 4,
              'Columns' => flat_columns,
              'Rows' => result.rows.map.each.with_index do |row, i|
                [i, row].flatten
              end
            )
          end

          def cmd_query(*args)
            cmd_query_help && return if help_args?(args)

            result = client.query(args.join(' ').to_s)
            table = format_result(result)

            print_line(table.to_s)
          end

          alias cmd_sql cmd_query
          alias cmd_sql_help cmd_query_help
        end
      end
    end
  end
end
