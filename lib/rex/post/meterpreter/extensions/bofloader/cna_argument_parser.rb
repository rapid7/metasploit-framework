# frozen_string_literal: true

module Rex
  module Post
    module Meterpreter
      module Extensions
        module Bofloader
          # Packs positional arguments extracted from a CNA alias.
          class CnaArgumentParser
            class Error < Rex::RuntimeError; end

            INTEGER_RANGES = {
              'int32' => (-2**31)..(2**31 - 1),
              'int16' => (-2**15)..(2**15 - 1)
            }.freeze

            # Creates an argument parser for a CNA alias.
            #
            # @param arguments [Array<Hash>] Ordered packed-value definitions.
            def initialize(arguments:)
              @arguments = arguments
            end

            # Converts CNA positionals into native bof_pack input.
            #
            # @param tokens [Array<String>] Positional command arguments.
            # @return [Hash] Format string and typed values.
            def parse(tokens)
              positions = @arguments.filter_map { |argument| argument['position'] }.uniq
              required_count = @arguments.filter_map { |argument| argument['position'] + 1 if argument['required'] }.max || 0
              expected_count = positions.empty? ? 0 : positions.max + 1

              raise Error, "Missing positional BOF argument #{required_count}" if tokens.length < required_count
              raise Error, "Too many positional BOF arguments (expected at most #{expected_count})" if tokens.length > expected_count

              values = @arguments.map do |argument|
                next argument['fixed'] if argument.key?('fixed')

                raw_value = tokens[argument['position']]
                raw_value = argument['default'] if raw_value.nil? && argument.key?('default')
                raise Error, "Missing positional BOF argument #{argument['position'] + 1}" if raw_value.nil?

                coerce(argument, raw_value)
              end
              { 'format' => @arguments.empty? ? nil : @arguments.map { |argument| argument['format'] }.join, 'values' => values }
            end

            private

            def coerce(argument, value)
              case argument['type']
              when 'bytes'
                value.b
              when 'file'
                unless ::File.file?(value) && ::File.readable?(value)
                  raise Error, "Positional BOF argument #{argument['position'] + 1} references an unreadable file"
                end

                ::File.binread(value)
              when *INTEGER_RANGES.keys
                parse_integer(argument, value)
              when 'string', 'wstring'
                value
              end
            end

            def parse_integer(argument, value)
              literal = value.delete_prefix('-')
              base = literal.start_with?('0x') ? 16 : 10
              integer = value.start_with?('-') ? -literal.to_i(base) : literal.to_i(base)
              unless value.match?(/\A-?(?:0x[0-9a-fA-F]+|[0-9]+)\z/) && INTEGER_RANGES.fetch(argument['type']).cover?(integer)
                raise Error, "Positional BOF argument #{argument['position'] + 1} is not a valid #{argument['type']}"
              end

              integer
            end
          end
        end
      end
    end
  end
end
