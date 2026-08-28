# frozen_string_literal: true

require 'rex/parser/arguments'
require 'rex/post/meterpreter/ui/console/command_dispatcher'

module Rex
  module Post
    module Meterpreter
      module Ui
        # Adds declarative YAML aliases to a Meterpreter console.
        class Console::MeterpreterAliasDispatcher
          include Console::CommandDispatcher

          # Creates a dispatcher for an immutable alias registry.
          #
          # @param shell [Rex::Post::Meterpreter::Ui::Console] Meterpreter console.
          # @param registry [Hash] Normalized configuration registry.
          # @param reload_callback [#call, nil] Callback used by `aliases_reload`.
          def initialize(shell, registry:, reload_callback: nil)
            super(shell)
            @registry = registry
            @reload_callback = reload_callback
            define_alias_methods
          end

          # Returns commands available to this Meterpreter session.
          #
          # @return [Hash<String, String>] Command descriptions keyed by command name.
          def commands
            management_commands.merge(
              available_aliases.transform_values { |definition| definition['description'] }
            )
          end

          # Returns the dispatcher name.
          #
          # @return [String] Dispatcher name.
          def name
            'Meterpreter Aliases'
          end

          # Lists aliases available in the current session.
          #
          # @param args [Array<String>] Optional help flag.
          # @return [Boolean] Whether the command was handled successfully.
          def cmd_aliases(*args)
            return cmd_aliases_help if args == ['-h']

            if args.any?
              print_error('Usage: aliases')
              return false
            end

            print_line("Configuration: #{@registry['path']}")
            print_line
            commands = available_aliases
            if commands.empty?
              print_status('No aliases are available for this platform')
              return true
            end

            width = commands.keys.map(&:length).max
            commands.sort.each do |alias_name, definition|
              print_line("#{alias_name.ljust(width)}  #{definition['description']}")
            end
            true
          end

          # Displays help for the aliases command.
          #
          # @return [Boolean] Always true.
          def cmd_aliases_help
            print_line('Usage: aliases')
            print_line
            print_line('Lists YAML aliases available to this Meterpreter session.')
            true
          end

          # Reloads the active alias file.
          #
          # @param args [Array<String>] Optional help flag.
          # @return [Boolean] Whether reload succeeded.
          def cmd_aliases_reload(*args)
            return cmd_aliases_reload_help if args == ['-h']

            if args.any?
              print_error('Usage: aliases_reload')
              return false
            end

            unless @reload_callback
              print_error('Alias reload is unavailable')
              return false
            end

            @reload_callback.call
          end

          # Displays help for the aliases_reload command.
          #
          # @return [Boolean] Always true.
          def cmd_aliases_reload_help
            print_line('Usage: aliases_reload')
            print_line
            print_line('Reloads the active Meterpreter alias YAML file.')
            true
          end

          private

          def management_commands
            {
              'aliases' => 'List Meterpreter YAML aliases',
              'aliases_reload' => 'Reload Meterpreter YAML aliases'
            }
          end

          def available_aliases
            @registry['aliases'].select do |_alias_name, definition|
              definition['platforms'].include?(client.platform)
            end
          end

          def define_alias_methods
            @registry['aliases'].each_key do |alias_name|
              define_singleton_method("cmd_#{alias_name}") do |*args|
                execute_alias(alias_name, args)
              end
              define_singleton_method("cmd_#{alias_name}_help") do |*_args|
                alias_help(alias_name)
              end
              define_singleton_method("cmd_#{alias_name}_tabs") do |_str, words|
                alias_tabs(alias_name, words)
              end
            end
          end

          def execute_alias(alias_name, args)
            definition = @registry['aliases'].fetch(alias_name)
            unless definition['platforms'].include?(client.platform)
              print_error("Alias '#{alias_name}' does not support platform #{client.platform}")
              return false
            end

            parser = alias_parser(definition)
            valid_switches = parser.option_keys
            unknown_switch = args.find { |argument| argument.start_with?('-') && !valid_switches.include?(argument) }
            if unknown_switch
              print_error("Unknown argument: #{unknown_switch}")
              return false
            end

            positional_values = []
            selected_switches = []
            parser.parse(args) do |option, _index, value|
              if option.nil?
                positional_values << value
              elsif option == '-h'
                alias_help(alias_name)
                return true
              else
                selected_switches << option
              end
            end

            positionals = definition['positional']
            if positional_values.length > positionals.length
              print_error("Alias '#{alias_name}' accepts at most #{positionals.length} positional arguments")
              return false
            end

            missing = positionals.each_with_index.find do |positional, index|
              positional['required'] && positional_values[index].nil?
            end
            if missing
              print_error("Missing required argument: #{missing.first['option']}")
              return false
            end

            options = definition['defaults'].dup
            architecture_options = definition['architecture_options']
            if architecture_options
              architecture = normalized_architecture(client.sys.config.sysinfo['Architecture'])
              selected_options = architecture_options['values'][architecture]
              unless selected_options
                print_error("Alias '#{alias_name}' does not support architecture #{architecture}")
                return false
              end
              options.merge!(selected_options)
            end

            selected_switches.each do |switch_name|
              options.merge!(definition['switches'].fetch(switch_name)['options'])
            end
            positional_values.each_with_index do |value, index|
              options[positionals[index]['option']] = value
            end

            module_options = options.map { |option, value| "#{option}=#{value}" }
            client.execute_script(definition['module'], *module_options)
            true
          end

          def alias_parser(definition)
            switches = definition['switches'].transform_values do |switch|
              [false, switch['description']]
            end
            switches['-h'] = [false, 'Help menu']
            Rex::Parser::Arguments.new(switches)
          end

          def alias_help(alias_name)
            definition = @registry['aliases'].fetch(alias_name)
            arguments = definition['positional'].map do |positional|
              name = "<#{positional['option']}>"
              positional['required'] ? name : "[#{name}]"
            end
            print_line("Usage: #{([alias_name] + arguments + ['[options]']).join(' ')}")
            print_line
            print_line(definition['description'])
            print(alias_parser(definition).usage)
            true
          end

          def alias_tabs(alias_name, words)
            definition = @registry['aliases'].fetch(alias_name)
            return [] unless definition['platforms'].include?(client.platform)

            selected = words.select { |word| word.start_with?('-') }
            alias_parser(definition).option_keys - selected
          end

          def normalized_architecture(architecture)
            architecture = architecture&.strip
            return ARCH_ARMLE if %w[armv5l armv6l armv7l].include?(architecture)

            architecture
          end
        end
      end
    end
  end
end
