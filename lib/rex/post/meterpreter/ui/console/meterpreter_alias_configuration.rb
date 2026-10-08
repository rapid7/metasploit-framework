# frozen_string_literal: true

require 'yaml'

module Rex
  module Post
    module Meterpreter
      module Ui
        # Loads, validates, and normalizes Meterpreter aliases from YAML.
        class Console::MeterpreterAliasConfiguration
          class Error < Rex::RuntimeError; end

          SCHEMA_VERSION = 1
          ROOT_KEYS = %w[version aliases].freeze
          ALIAS_KEYS = %w[description platforms module positional defaults switches architecture_options].freeze
          POSITIONAL_KEYS = %w[option required].freeze
          SWITCH_KEYS = %w[description options].freeze
          ARCHITECTURE_KEYS = %w[source values].freeze
          COMMAND_NAME_PATTERN = /\A[a-z][a-z0-9_-]*\z/
          OPTION_NAME_PATTERN = /\A[A-Za-z][A-Za-z0-9_]*\z/
          MODULE_NAME_PATTERN = %r{\A(?:post|exploit)/[a-z0-9_/]+\z}
          SWITCH_NAME_PATTERN = /\A-[A-Za-z]\z/

          # Loads and validates a Meterpreter alias YAML file.
          #
          # @param path [String] YAML configuration path.
          # @param module_validator [#call, nil] Optional callable that validates module names.
          # @return [Hash] Immutable normalized configuration with `path` and `aliases` keys.
          def self.load(path:, module_validator: nil)
            expanded_path = ::File.expand_path(path)
            raise Error, "Meterpreter alias configuration does not exist: #{expanded_path}" unless ::File.file?(expanded_path)

            document = begin
              YAML.safe_load(::File.binread(expanded_path), permitted_classes: [], permitted_symbols: [], aliases: false)
            rescue Psych::Exception => e
              raise Error, "Unable to parse Meterpreter alias configuration #{expanded_path}: #{e.message}"
            rescue SystemCallError => e
              raise Error, "Unable to read Meterpreter alias configuration #{expanded_path}: #{e.message}"
            end

            root = validate_hash(document, 'configuration')
            reject_unknown_keys(root, ROOT_KEYS, 'configuration')
            raise Error, "Configuration key 'version' must be #{SCHEMA_VERSION}" unless root['version'] == SCHEMA_VERSION

            raw_aliases = validate_hash(root['aliases'], "configuration key 'aliases'")
            aliases = raw_aliases.each_with_object({}) do |(alias_name, raw_alias), result|
              validate_command_name(alias_name)
              result[alias_name] = normalize_alias(alias_name, raw_alias, module_validator)
            end

            deep_freeze('path' => expanded_path, 'aliases' => aliases)
          end

          class << self
            private

            def normalize_alias(alias_name, raw_alias, module_validator)
              definition = validate_hash(raw_alias, alias_context(alias_name))
              reject_unknown_keys(definition, ALIAS_KEYS, alias_context(alias_name))

              description = definition['description']
              unless description.is_a?(String) && !description.empty?
                invalid(alias_name, 'description', 'must be a non-empty string')
              end

              platforms = definition['platforms']
              unless platforms.is_a?(Array) && platforms.any? && platforms.all? { |platform| platform.is_a?(String) && !platform.empty? }
                invalid(alias_name, 'platforms', 'must be a non-empty array of strings')
              end

              module_name = definition['module']
              unless module_name.is_a?(String) && module_name.match?(MODULE_NAME_PATTERN)
                invalid(alias_name, 'module', 'must identify a post module or local exploit')
              end
              if module_validator && !module_validator.call(module_name)
                invalid(alias_name, 'module', "module is unavailable or unsupported: #{module_name}")
              end

              positional = normalize_positionals(alias_name, definition.fetch('positional', []))
              defaults = normalize_options(alias_name, 'defaults', definition.fetch('defaults', {}))
              switches = normalize_switches(alias_name, definition.fetch('switches', {}))
              architecture_options = normalize_architecture_options(alias_name, definition['architecture_options'])

              {
                'description' => description,
                'platforms' => platforms.uniq,
                'module' => module_name,
                'positional' => positional,
                'defaults' => defaults,
                'switches' => switches,
                'architecture_options' => architecture_options
              }
            end

            def normalize_positionals(alias_name, raw_positionals)
              invalid(alias_name, 'positional', 'must be an array') unless raw_positionals.is_a?(Array)

              required_seen = false
              options = raw_positionals.map.with_index do |raw_positional, index|
                key = "positional[#{index}]"
                positional = validate_hash(raw_positional, alias_context(alias_name, key))
                reject_unknown_keys(positional, POSITIONAL_KEYS, alias_context(alias_name, key))
                validate_option_name(alias_name, key, positional['option'])
                required = positional.fetch('required', false)
                invalid(alias_name, key, "'required' must be true or false") unless [true, false].include?(required)
                invalid(alias_name, key, 'required positional arguments must precede optional ones') if required_seen && required
                required_seen ||= !required

                { 'option' => positional['option'], 'required' => required }
              end

              duplicate = options.map { |positional| positional['option'] }.tally.find { |_option, count| count > 1 }&.first
              invalid(alias_name, 'positional', "contains duplicate option: #{duplicate}") if duplicate
              options
            end

            def normalize_switches(alias_name, raw_switches)
              switches = validate_hash(raw_switches, alias_context(alias_name, 'switches'))
              switches.each_with_object({}) do |(switch_name, raw_switch), result|
                invalid(alias_name, 'switches', "invalid switch name: #{switch_name}") unless switch_name.is_a?(String) && switch_name.match?(SWITCH_NAME_PATTERN)
                invalid(alias_name, 'switches', "reserved switch name: #{switch_name}") if switch_name == '-h'

                switch = validate_hash(raw_switch, alias_context(alias_name, "switches.#{switch_name}"))
                reject_unknown_keys(switch, SWITCH_KEYS, alias_context(alias_name, "switches.#{switch_name}"))
                description = switch['description']
                unless description.is_a?(String) && !description.empty?
                  invalid(alias_name, "switches.#{switch_name}.description", 'must be a non-empty string')
                end

                result[switch_name] = {
                  'description' => description,
                  'options' => normalize_options(alias_name, "switches.#{switch_name}.options", switch.fetch('options', {}))
                }
              end
            end

            def normalize_architecture_options(alias_name, raw_architecture_options)
              return unless raw_architecture_options

              architecture_options = validate_hash(raw_architecture_options, alias_context(alias_name, 'architecture_options'))
              reject_unknown_keys(architecture_options, ARCHITECTURE_KEYS, alias_context(alias_name, 'architecture_options'))
              invalid(alias_name, 'architecture_options.source', "must be 'sysinfo'") unless architecture_options['source'] == 'sysinfo'

              values = validate_hash(architecture_options['values'], alias_context(alias_name, 'architecture_options.values'))
              invalid(alias_name, 'architecture_options.values', 'must not be empty') if values.empty?

              {
                'source' => 'sysinfo',
                'values' => values.each_with_object({}) do |(architecture, options), result|
                  unless architecture.is_a?(String) && !architecture.empty?
                    invalid(alias_name, 'architecture_options.values', 'architecture names must be non-empty strings')
                  end

                  result[architecture] = normalize_options(alias_name, "architecture_options.values.#{architecture}", options)
                end
              }
            end

            def normalize_options(alias_name, key, raw_options)
              options = validate_hash(raw_options, alias_context(alias_name, key))
              options.each_with_object({}) do |(option_name, value), result|
                validate_option_name(alias_name, key, option_name)
                invalid(alias_name, "#{key}.#{option_name}", 'must be a scalar value') unless scalar?(value)
                result[option_name] = value
              end
            end

            def scalar?(value)
              value.is_a?(String) || value.is_a?(Integer) || value == true || value == false || value.nil?
            end

            def validate_command_name(alias_name)
              raise Error, "Invalid Meterpreter alias name: #{alias_name}" unless alias_name.is_a?(String) && alias_name.match?(COMMAND_NAME_PATTERN)
              raise Error, "Reserved Meterpreter alias name: #{alias_name}" if %w[aliases aliases_reload].include?(alias_name)
            end

            def validate_option_name(alias_name, key, option_name)
              invalid(alias_name, key, "invalid module option name: #{option_name}") unless option_name.is_a?(String) && option_name.match?(OPTION_NAME_PATTERN)
            end

            def validate_hash(value, context)
              raise Error, "#{context} must be a hash" unless value.is_a?(Hash)

              value
            end

            def reject_unknown_keys(hash, allowed, context)
              unknown = hash.keys - allowed
              raise Error, "#{context} contains unknown key: #{unknown.first}" if unknown.any?
            end

            def invalid(alias_name, key, message)
              raise Error, "Alias '#{alias_name}' key '#{key}' #{message}"
            end

            def alias_context(alias_name, key = nil)
              context = "Alias '#{alias_name}'"
              context << " key '#{key}'" if key
              context
            end

            def deep_freeze(value)
              case value
              when Hash
                value.each do |key, child|
                  deep_freeze(key)
                  deep_freeze(child)
                end
              when Array
                value.each { |child| deep_freeze(child) }
              end
              value.freeze
            end
          end
        end
      end
    end
  end
end
