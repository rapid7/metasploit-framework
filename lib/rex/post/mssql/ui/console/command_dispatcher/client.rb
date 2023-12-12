# -*- coding: binary -*-

require 'pathname'
require 'reline'

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

          include Rex::Post::MSSQL::Ui::Console::CommandDispatcher

          #
          # Initializes an instance of the core command set using the supplied console
          # for interactivity.
          #
          # @param [Rex::Post::MSSQL::Ui::Console] console
          def initialize(console)
            super

            @db_search_results = []
          end

          #
          # List of supported commands.
          #
          # @return [Hash{String->String}]
          def commands
            cmds = {
              'query'   => 'Run a raw SQL query',
              'shell'   => 'Enter a raw shell where SQL queries can be executed',
            }

            reqs = {}

            filter_commands(cmds, reqs)
          end

          # @return [String]
          def name
            'MSSQL Client'
          end

          # @param [Object] args
          # @return [FalseClass, TrueClass]
          def help_args?(args)
            return false unless args.instance_of?(::Array)

            args.include?('-h') || args.include?('--help')
          end

          # @return [Object]
          def cmd_shell_help
            print_line 'Usage: shell'
            print_line
            print_line 'Go into a raw SQL shell where SQL queries can be executed.'
            print_line 'To exit, type `exit`, `quit`, `end` or `stop`.'
            print_line
          end

          # @param [Array] args
          # @return [Object]
          def cmd_shell(*args)
            cmd_shell_help && return if help_args?(args)

            prompt_proc_before = ::Reline.prompt_proc

            ::Reline.prompt_proc = proc { |line_buffer| line_buffer.each_with_index.map { |_line, i| i > 0 ? 'SQL *> ' : 'SQL >> ' } }

            stop_words = %w[stop s exit e end quit q].freeze

            finished = false
            loop do
              begin
                raw_query = ::Reline.readmultiline('SQL >> ', use_history = true) do |multiline_input|
                  finished = stop_words.include?(multiline_input.split.last)
                  finished || (multiline_input.split.last && !multiline_input.split.last.end_with?('\\'))
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

          # @return [Object]
          def cmd_query_help
            print_line 'Usage: query'
            print_line
            print_line 'Run a raw SQL query on the target.'
            print_line 'Examples:'
            print_line
            print_line '    query select @@version;'
            print_line '    query select user_name();'
            print_line '    query select name from master.dbo.sysdatabases;'
            print_line
          end

          # @param [Array] result The result of an SQL query to format.
          def format_result(result)
            columns = ['#']

            unless result.is_a?(Array)
              result.fields.each { |field| columns.append(field.name) }

              ::Rex::Text::Table.new(
                'Header' => 'Query Result',
                'Indent' => 4,
                'Columns' => columns,
                'Rows' => result.map.each.with_index { |row, i| [i, row].flatten }
              )
            end
          end

          # @param [Array] args SQL query
          # @return [Object]
          def cmd_query(*args)
            if help_args?(args)
              cmd_query_help
              return
            end

            query = args.join(' ').to_s
            client.mssql_query(query, true) || []
          end
        end
      end
    end
  end
end
