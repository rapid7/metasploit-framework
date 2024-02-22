# -*- coding: binary -*-

module Rex
  module Post
    module Sql
      module Ui
        module Console
          module CommandDispatcher

            ###
            #
            # Core Generic SQL client commands
            #
            ###
            module Client

              include Rex::Post::Sql::Ui::Console::CommandDispatcher

              #
              # Initializes an instance of the core command set using the supplied console
              # for interactivity.
              #
              # @param console The protocol-specific Rex Ui Console
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

              # @return [String] The name of the client
              def name
                raise ::NotImplementedError
              end

              # @param [Array] args An array of arguments passed in to a command
              # @return [TrueClass, FalseClass] True if the array contains '-h' or '--help', else false.
              def help_args?(args)
                return false unless args.instance_of?(::Array)

                args.include?('-h') || args.include?('--help')
              end

              def cmd_shell_help
                print_line 'Usage: shell'
                print_line
                print_line 'Go into a raw SQL shell where SQL queries can be executed.'
                print_line "To exit, type 'exit', 'quit', 'end' or 'stop'."
                print_line
              end

              def cmd_shell(*args)
                if help_args?(args)
                  cmd_shell_help
                  return
                end

                console = shell
                # Pass in self so that we can call cmd_query in subsequent calls
                console.interact_with_client(client_dispatcher: self)
              end

              def normalise_sql_result(result)
                raise ::NotImplementedError
              end

              # Take in a normalised SQL result and print it.
              # If there are any errors, print those instead.
              # @param [Hash {Symbol => Array, Symbol => Array, Symbol => Array}] result A hash of 'rows', 'columns' and 'errors'
              def format_result(result)
                if result[:errors].any?
                  return "Query has failed. Reasons: #{result[:errors].join(', ')}"
                end

                number_column = ['#']
                columns = [number_column, result[:columns]].flatten
                rows = result[:rows].map.each_with_index do |row, i|
                  [i, row].flatten
                end

                ::Rex::Text::Table.new(
                  'Header' => 'Response',
                  'Indent' => 4,
                  'Columns' => columns,
                  'Rows' => rows
                )
              end

              def cmd_query_help
                raise ::NotImplementedError
              end

              def run_query(query)
                begin
                  result = client.query(query)
                rescue ::RuntimeError, ::StandardError => e
                  elog("Running query '#{query}' failed on session #{self.inspect}", error: e)
                  return { status: :error, result: { errors: [e] } }
                end

                if result.respond_to? :cmd_tag
                  print_status result.cmd_tag
                  print_line
                end

                { status: :success, result: result }
              end

              def cmd_query(*args)
                if help_args?(args)
                  cmd_query_help
                  return
                end

                result = run_query(args.join(' '))

                normalised_result = result[:status] == :success ? normalise_sql_result(result[:result]) : result[:result]
                formatted_result = format_result(normalised_result)

                normalised_result[:errors].any? ? print_error(formatted_result.to_s) : print_line(formatted_result.to_s)
              end

              def process_query(query: '')
                return '' if query.empty?

                query.lines.each.map { |line| line.chomp.chomp('\\').strip }.reject(&:empty?).compact.join(' ')
              end
            end
          end
        end
      end
    end
  end
end
