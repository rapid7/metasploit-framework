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
            if help_args?(args)
              cmd_shell_help
              return
            end

            stop_words = %w[stop s exit e end quit q].freeze

            # Allow the user to query the DB in a loop.
            finished = false
            until finished
              begin
                # This needs to be here, otherwise the `ensure` block would reset it to the previous
                # value after a single query, meaning future queries would have the default prompt_block.
                prompt_proc_before = ::Reline.prompt_proc
                ::Reline.prompt_proc = proc { |line_buffer| line_buffer.each_with_index.map { |_line, i| i > 0 ? 'SQL *> ' : 'SQL >> ' } }

                # This will loop until it receives `true`.
                raw_query = ::Reline.readmultiline('SQL >> ', use_history = true) do |multiline_input|
                  # In the case only a stop word was input, exit out of the REPL shell
                  finished = multiline_input.split.count == 1 && stop_words.include?(multiline_input.split.last)
                  # Accept the input until the current line does not end with '\', similar to a shell
                  finished || multiline_input.split.empty? || !multiline_input.split.last&.end_with?('\\')
                end
              rescue ::Interrupt => _e
                finished = true
              ensure
                ::Reline.prompt_proc = prompt_proc_before
              end

              if finished
                print_status 'Exiting Shell mode.'
                return
              end

              formatted_query = process_query(query: raw_query)

              unless formatted_query.empty?
                print_status "Running SQL Command: '#{formatted_query}'"
                cmd_query(formatted_query)
              end
            end
          end

          def cmd_query_help
            print_line 'Usage: query'
            print_line
            print_line 'Run a raw SQL query on the target.'
            print_line
            print_line 'Examples:'
            print_line "\tquery SELECT user;"
            print_line "\tquery SELECT version();"
            print_line "\tquery SELECT * FROM pg_catalog.pg_tables;"
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
            if help_args?(args)
              cmd_query_help
              return
            end

            begin
              result = client.query(args.join(' ').to_s)
            rescue ::RuntimeError => e
              print_error "Query result: #{e}"
              print_line
              return
            end

            print_status result.cmd_tag
            print_line

            unless result.rows.empty?
              table = format_result(result)
              print_line(table.to_s)
            end
          end

          def process_query(query: '')
            return '' if query.empty?

            query.lines.each.map { |line| line.chomp("\\\n").strip }.reject(&:empty?).compact.join(' ')
          end
        end
      end
    end
  end
end
