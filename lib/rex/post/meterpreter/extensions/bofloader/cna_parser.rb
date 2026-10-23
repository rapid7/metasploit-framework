# frozen_string_literal: true

module Rex
  module Post
    module Meterpreter
      module Extensions
        module Bofloader
          # Statically imports conventional BOF launchers from Aggressor scripts.
          class CnaParser
            class Error < Rex::RuntimeError; end
            class Unsupported < StandardError; end

            FORMAT_TYPES = {
              'b' => 'bytes',
              'i' => 'int32',
              's' => 'int16',
              'z' => 'string',
              'Z' => 'wstring'
            }.freeze
            INTEGER_RANGES = {
              'i' => (-2**31)..(2**31 - 1),
              's' => (-2**15)..(2**15 - 1)
            }.freeze
            REQUIRED_INTRINSICS = %w[
              barch beacon_command_register beacon_inline_execute bof_pack iff openf readb script_resource
            ].freeze
            NULL = Object.new.freeze
            PARAMETER_PATTERN = /\A\$(\d+)\z/
            USAGE_MARKER_PATTERN = /\A(?:(?<optional>optional|opt)|required)(?=\s|:|\z)\s*:?\s*/i
            VARIABLE_PATTERN = /\A\$[a-zA-Z_]\w*\z/

            # Parses an Aggressor script.
            #
            # @param path [String] Aggressor script path.
            # @return [Hash] Normalized BOF catalog.
            def self.parse(path:)
              new(path: path).parse
            end

            # Creates a CNA parser.
            #
            # @param path [String] Aggressor script path.
            def initialize(path:)
              @path = path
              @base_path = ::File.dirname(path)
            end

            # Returns a normalized catalog of statically supported CNA aliases.
            #
            # @return [Hash] Catalog and per-alias import warnings.
            def parse
              source = read_source
              @code = remove_comments(source)
              @subroutines = named_blocks('sub')
              @overridden_intrinsics = (declared_block_names('sub') + declared_block_names('inline')).uniq & REQUIRED_INTRINSICS

              aliases = named_blocks('alias')
              registrations = command_registrations
              bofs = {}
              warnings = []
              duplicate_aliases = aliases.map(&:first).tally.select { |_name, count| count > 1 }.keys
              duplicate_aliases.each { |alias_name| warnings << "CNA alias '#{alias_name}' is declared more than once" }

              aliases.each do |alias_name, body|
                next if duplicate_aliases.include?(alias_name)
                next if function_calls(body, 'beacon_inline_execute').empty?

                begin
                  definition = import_alias(alias_name, body, registrations[alias_name])
                  bofs[alias_name] = definition
                rescue Unsupported => e
                  warnings << "CNA alias '#{alias_name}' was skipped: #{e.message}"
                end
              end

              if bofs.empty?
                reason = warnings.first || 'the script does not contain a beacon_inline_execute alias'
                raise Error, "No compatible BOFs found in CNA script #{@path}: #{reason}"
              end

              { 'path' => @path, 'bofs' => bofs, 'warnings' => warnings }
            end

            private

            def read_source
              source = ::File.binread(@path).force_encoding(::Encoding::UTF_8)
              raise Error, "CNA script is not valid UTF-8: #{@path}" unless source.valid_encoding?

              source
            rescue SystemCallError => e
              raise Error, "Unable to read CNA script #{@path}: #{e.message}"
            end

            def import_alias(alias_name, body, registration)
              execute_calls = function_calls(body, 'beacon_inline_execute')
              raise Unsupported, 'multiple beacon_inline_execute calls are not statically supported' unless execute_calls.length == 1
              raise Unsupported, 'beacon_inline_execute must be an unconditional top-level call' unless function_calls(body, 'beacon_inline_execute', top_level: true).length == 1
              raise Unsupported, 'conditional return or throw can prevent beacon_inline_execute' if flow_control_exit_before_call?(body, 'beacon_inline_execute')
              raise Unsupported, 'assert can prevent beacon_inline_execute' if assertion_before_call?(body, 'beacon_inline_execute')

              execute_arguments = execute_calls.first
              raise Unsupported, 'beacon_inline_execute does not specify a BOF and entry point' if execute_arguments.length < 3
              raise Unsupported, 'beacon_inline_execute has unsupported extra arguments' if execute_arguments.length > 4

              execute_offset = function_call_offset(body, 'beacon_inline_execute')
              body_before_execute = body[0...execute_offset]
              validate_required_intrinsics!(body_before_execute)
              validate_required_intrinsics!(execute_arguments.join(','))
              validate_required_intrinsic!('beacon_inline_execute')
              analysis = code_analysis(body_before_execute)
              raise Unsupported, 'beacon_inline_execute must target the alias Beacon' unless unmodified_parameter?(execute_arguments[0], analysis, '$1', before: execute_offset)

              template, replacements = bof_template(execute_arguments[1], analysis, before: execute_offset)
              files = bof_files(template, replacements)
              entry = literal(execute_arguments[2])
              raise Unsupported, 'the BOF entry point is dynamic' unless entry.is_a?(String) && !entry.empty?

              usage = registration && registration['usage']
              packed_arguments = packed_arguments(execute_arguments[3], analysis, before: execute_offset)
              decorate_arguments!(packed_arguments, usage)

              {
                'description' => registration ? registration['description'] : "Imported from #{::File.basename(@path)}",
                'authors' => [],
                'references' => [],
                'files' => files,
                'entry' => entry,
                'arguments' => packed_arguments,
                'argument_style' => 'positional',
                'usage' => usage || alias_name
              }
            end

            def command_registrations
              return {} if @overridden_intrinsics.include?('beacon_command_register')

              function_calls(@code, 'beacon_command_register', top_level: true).each_with_object({}) do |arguments, result|
                name = literal(arguments[0])
                description = literal(arguments[1])
                next unless name.is_a?(String) && !name.empty? && description.is_a?(String) && !description.empty?

                usage = literal(arguments[2])
                result[name] = {
                  'description' => description,
                  'usage' => usage.is_a?(String) && !usage.empty? ? usage : name
                }
              rescue Unsupported
                next
              end
            end

            def packed_arguments(argument_expression, analysis, before:)
              return [] if argument_expression.nil? || literal(argument_expression).nil?

              expression = argument_expression.strip
              if expression.match?(VARIABLE_PATTERN)
                assignment = assignment_value(analysis, expression, before: before)
                expression = assignment.fetch('value')
                before = assignment.fetch('offset')
              end

              pack_arguments = exact_function_call(expression, 'bof_pack')
              raise Unsupported, 'arguments are not assigned by one bof_pack call' unless pack_arguments
              raise Unsupported, 'bof_pack must target the alias Beacon' unless unmodified_parameter?(pack_arguments[0], analysis, '$1', before: before)

              format = literal(pack_arguments[1])
              unless format.is_a?(String) && !format.empty? && format.match?(/\A[biszZ]+\z/)
                raise Unsupported, 'bof_pack uses a dynamic or invalid format'
              end
              if pack_arguments.length != format.length + 2
                raise Unsupported, 'bof_pack format and argument counts do not match'
              end

              definitions = format.chars.zip(pack_arguments.drop(2)).map do |format_character, value_expression|
                packed_value(format_character, value_expression, analysis, [], before: before)
              end
              positions = definitions.filter_map { |definition| definition['position'] }.uniq.sort
              if positions.each_with_index.any? { |position, index| position != index }
                raise Unsupported, 'CNA positional arguments are transformed outside bof_pack'
              end

              definitions
            end

            def packed_value(format_character, expression, analysis, seen, before:)
              value = literal(expression, binary: format_character == 'b')
              unless value.equal?(NULL)
                fixed = value.nil? && format_character == 'b' ? String.new.b : value
                raise Unsupported, "#{format_character} argument has an incompatible literal" unless compatible_literal?(format_character, fixed)

                return packed_definition(format_character).merge('fixed' => fixed)
              end

              if (match = expression.strip.match(PARAMETER_PATTERN))
                raise Unsupported, "#{match[0]} has a dynamic assignment" if parameter_modified?(analysis, match[0], before: before)

                position = match[1].to_i - 2
                raise Unsupported, 'Beacon ID cannot be used as a BOF argument' if position.negative?

                return packed_definition(format_character).merge('position' => position, 'required' => true)
              end

              variable = expression.strip
              if variable.match?(VARIABLE_PATTERN)
                raise Unsupported, "recursive assignment for #{variable}" if seen.include?(variable)

                assignment = assignment_value(analysis, variable, before: before)
                return packed_value(format_character, assignment.fetch('value'), analysis, seen + [variable], before: assignment.fetch('offset'))
              end

              optional = optional_value(format_character, expression, analysis, seen, before: before)
              return optional if optional

              if format_character == 'b'
                position = file_position(expression, analysis, seen, before: before)
                return packed_definition(format_character).merge('type' => 'file', 'raw' => false, 'position' => position, 'required' => true)
              end

              raise(
                Unsupported,
                "cannot statically evaluate packed expression #{expression.strip}"
              )
            end

            def optional_value(format_character, expression, analysis, seen, before:)
              arguments = exact_function_call(expression, 'iff')
              return unless arguments&.length == 3

              condition, true_expression, false_expression = arguments
              match = condition.strip.match(/\A-istrue\s+(\$\d+)\z/)
              return unless match && true_expression.strip == match[1]

              default = literal(false_expression, binary: format_character == 'b')
              return if default.equal?(NULL) || !compatible_literal?(format_character, default)

              packed_value(format_character, match[1], analysis, seen, before: before).merge('required' => false, 'default' => default)
            end

            def file_position(expression, analysis, seen, stage = :readb, before:)
              variable = unwrap_parentheses(expression)
              if variable.match?(VARIABLE_PATTERN)
                raise Unsupported, "recursive assignment for #{variable}" if seen.include?(variable)

                assignment = assignment_value(analysis, variable, before: before)
                return file_position(assignment.fetch('value'), analysis, seen + [variable], stage, before: assignment.fetch('offset'))
              end

              case stage
              when :readb
                arguments = exact_function_call(variable, 'readb')
                if arguments&.length == 2 && arguments[1].strip == '-1'
                  return file_position(arguments.first, analysis, seen, :openf, before: before)
                end
              when :openf
                arguments = exact_function_call(variable, 'openf')
                return file_position(arguments.first, analysis, seen, :parameter, before: before) if arguments&.length == 1
              when :parameter
                if (match = variable.match(PARAMETER_PATTERN))
                  raise Unsupported, "#{match[0]} has a dynamic assignment" if parameter_modified?(analysis, match[0], before: before)

                  position = match[1].to_i - 2
                  raise Unsupported, 'Beacon ID cannot identify a local file' if position.negative?

                  return position
                end
              end

              raise Unsupported, 'binary file arguments must use readb(openf(path), -1)'
            end

            def packed_definition(format_character)
              {
                'name' => nil,
                'description' => nil,
                'type' => FORMAT_TYPES.fetch(format_character),
                'format' => format_character,
                'raw' => format_character == 'b',
                'required' => false,
                'choices' => {}
              }
            end

            def compatible_literal?(format_character, value)
              case format_character
              when 'b'
                value.is_a?(String)
              when 'i', 's'
                value.is_a?(Integer) && INTEGER_RANGES.fetch(format_character).cover?(value)
              when 'z', 'Z'
                value.is_a?(String)
              end
            end

            def decorate_arguments!(definitions, usage)
              argument_hints = usage_argument_hints(usage)
              used_names = {}
              definitions.each do |definition|
                next if definition.key?('fixed')

                position = definition['position']
                hint = argument_hints[position]
                base_name = hint&.fetch('name') || "argument_#{position + 1}"
                name = unique_name(base_name, used_names)
                definition['name'] = name
                definition['description'] = "CNA positional argument #{position + 1}"

                if hint&.fetch('optional') && definition['required'] && definition['type'] != 'file'
                  definition['required'] = false
                  definition['default'] = default_argument_value(definition['type'])
                end
              end
            end

            def usage_argument_hints(usage)
              return [] unless usage

              usage.scan(/<([^>]+)>|\[([^\]]+)\]/).map do |angle, square|
                description = angle || square
                marker = description.match(USAGE_MARKER_PATTERN)
                optional = !marker&.[](:optional).nil?
                description = description.delete_prefix(marker[0]) if marker
                candidate = description[/[a-zA-Z][a-zA-Z0-9_-]*/]
                next unless candidate

                { 'name' => candidate.downcase.tr('-', '_'), 'optional' => optional }
              end.compact
            end

            def default_argument_value(type)
              case type
              when 'bytes'
                String.new.b
              when 'int16', 'int32'
                0
              when 'string', 'wstring'
                String.new
              end
            end

            def unique_name(base_name, used_names)
              count = used_names[base_name] = used_names.fetch(base_name, 0) + 1
              count == 1 ? base_name : "#{base_name}_#{count}"
            end

            def bof_template(data_expression, analysis, before:)
              expression, read_count, before = resolve_bof_expression(data_expression, analysis, [], before: before)
              resource = exact_function_call(expression, 'script_resource')
              if resource&.length == 1
                validate_architecture_variables!(resource.first, analysis, before: before)
                validate_bof_read_count!(read_count)
                return [resource.first, {}]
              end

              helpers = @subroutines.filter_map do |name, subroutine_body|
                invocation = exact_function_call(expression, name)
                next unless invocation

                [subroutine_body, invocation]
              end
              raise Unsupported, 'BOF helper is declared more than once' if helpers.length > 1

              if helpers.one?
                subroutine_body, invocation = helpers.first
                template, helper_read_count = subroutine_bof_template(subroutine_body, invocation)
                validate_bof_read_count!(read_count + helper_read_count)

                replacements = invocation.each_with_index.each_with_object({}) do |(argument, index), result|
                  value = literal(argument)
                  result["$#{index + 1}"] = value unless value.equal?(NULL)
                end
                return [template, replacements]
              end

              raise Unsupported, 'cannot determine the BOF path'
            end

            def subroutine_bof_template(body, invocation)
              returns = return_expressions(body)
              raise Unsupported, 'BOF helper does not have one static return value' unless returns.length == 1
              raise Unsupported, 'BOF helper return must be unconditional and top-level' unless return_expressions(body, top_level: true).length == 1

              return_offset = keyword_offset(body, 'return')
              body_before_return = body[0...return_offset]
              validate_required_intrinsics!(body_before_return)
              validate_required_intrinsics!(returns.first)
              raise Unsupported, 'flow control can prevent the BOF helper return' if control_keyword_before?(body, return_offset, %w[return throw assert])

              analysis = code_analysis(body_before_return)
              expression, read_count, before = resolve_bof_expression(returns.first, analysis, [], before: return_offset)
              resource = exact_function_call(expression, 'script_resource')
              raise Unsupported, 'BOF helper does not return one resource path' unless resource&.length == 1

              changed_parameters = template_parameters(resource.first).select { |parameter| parameter_modified?(analysis, parameter, before: before) }
              raise Unsupported, "#{changed_parameters.first} has a dynamic assignment" unless changed_parameters.empty?

              validate_architecture_variables!(resource.first, analysis, before: before, invocation: invocation)
              [resource.first, read_count]
            end

            def resolve_bof_expression(expression, analysis, seen, stage = :optional_readb, before:)
              expression = unwrap_parentheses(expression)
              if expression.match?(VARIABLE_PATTERN)
                raise Unsupported, "recursive assignment for #{expression}" if seen.include?(expression)

                assignment = assignment_value(analysis, expression, before: before)
                return resolve_bof_expression(assignment.fetch('value'), analysis, seen + [expression], stage, before: assignment.fetch('offset'))
              end

              case stage
              when :optional_readb
                readb_arguments = exact_function_call(expression, 'readb')
                if readb_arguments
                  raise Unsupported, 'BOF data must use exactly one readb(openf(path), -1)' unless readb_arguments.length == 2 && readb_arguments[1].strip == '-1'

                  return resolve_bof_expression(readb_arguments.first, analysis, seen, :openf, before: before)
                end

                raise Unsupported, 'BOF data must use exactly one readb(openf(path), -1)' if exact_function_call(expression, 'openf')

                return [expression, 0, before]
              when :openf
                openf_arguments = exact_function_call(expression, 'openf')
                if openf_arguments&.length == 1
                  resolved_expression, read_count, before = resolve_bof_expression(openf_arguments.first, analysis, seen, :path, before: before)
                  return [resolved_expression, read_count + 1, before]
                end
              when :path
                return [expression, 0, before] unless exact_function_call(expression, 'readb') || exact_function_call(expression, 'openf')
              end

              raise Unsupported, 'BOF data must use exactly one readb(openf(path), -1)'
            end

            def validate_bof_read_count!(read_count)
              raise Unsupported, 'BOF data must use exactly one readb(openf(path), -1)' unless read_count == 1
            end

            def unwrap_parentheses(expression)
              expression = expression.strip
              expression = expression[1...-1].strip while expression.start_with?('(') && matching_delimiter(expression, 0, '(', ')') == expression.length - 1
              expression
            end

            def return_expressions(code, top_level: false)
              expressions = []
              masked_code = mask_string_literals(code)
              quote = nil
              escaped = false
              index = 0

              while index < code.length
                character = code[index]
                if quote
                  if escaped
                    escaped = false
                  elsif character == '\\'
                    escaped = true
                  elsif character == quote
                    quote = nil
                  end
                elsif ["'", '"'].include?(character)
                  quote = character
                elsif (!top_level || top_level_offset?(masked_code, index)) && statement_keyword_at?(masked_code, index, 'return')
                  expression_start = index + 6
                  terminator = matching_terminator(code, expression_start, ';')
                  break unless terminator

                  expressions << code[expression_start...terminator].strip
                  index = terminator
                end
                index += 1
              end

              expressions
            end

            def bof_files(template, replacements)
              architecture_variables = ['$barch', '$arch']
              x64_replacements = replacements.merge(architecture_variables.to_h { |variable| [variable, 'x64'] })
              x86_replacements = replacements.merge(architecture_variables.to_h { |variable| [variable, 'x86'] })
              x64_path = resource_path(template, x64_replacements)
              x86_path = resource_path(template, x86_replacements)
              return { 'x64' => x64_path, 'x86' => x86_path } unless x64_path == x86_path

              architecture = path_architecture(x64_path)
              architecture ? { architecture => x64_path } : { 'x64' => x64_path, 'x86' => x64_path }
            end

            def resource_path(expression, replacements)
              parts = split_top_level(expression, separator: '.')
              evaluated = parts.map do |part|
                stripped_part = part.strip
                if string_literal?(stripped_part)
                  value = parse_string(stripped_part)
                  next value if stripped_part.start_with?("'")

                  raise Unsupported, 'BOF path contains an escaped dynamic variable' if stripped_part.include?('\\$')
                  if stripped_part.match?(/\\(?:x24|u0024)/i)
                    raise Unsupported, 'BOF path contains an encoded dollar sign'
                  end

                  value.gsub!(/\s*\$\+\s*/, '')
                  unless replacements.empty?
                    replacement_pattern = Regexp.union(replacements.keys.map { |variable| /#{Regexp.escape(variable)}\b/ })
                    value = value.gsub(replacement_pattern) { |variable| replacements.fetch(variable).to_s }
                  end
                  raise Unsupported, 'BOF path still contains dynamic variables' if value.include?('$')

                  value
                elsif replacements.key?(stripped_part)
                  replacements.fetch(stripped_part).to_s
                else
                  raise Unsupported, "BOF path contains dynamic expression #{stripped_part}"
                end
              end.join
              raise Unsupported, 'BOF path contains a null byte' if evaluated.include?("\0")

              ::File.expand_path(evaluated.tr('\\', ::File::SEPARATOR), @base_path)
            end

            def path_architecture(path)
              begin
                if ::File.file?(path) && ::File.readable?(path)
                  machine = ::File.binread(path, 2).unpack1('v')
                  return { 0x8664 => 'x64', 0x014c => 'x86' }[machine]
                end
              rescue SystemCallError
                # Fall through to path-name inference when the file cannot be read.
              end

              normalized_path = path.downcase.tr('\\', '/')
              return 'x64' if normalized_path.match?(%r{(?:\A|[._/-])x64(?:[._/-]|\z)})
              return 'x86' if normalized_path.match?(%r{(?:\A|[._/-])x86(?:[._/-]|\z)})
            end

            def validate_architecture_variables!(template, analysis, before:, invocation: nil)
              architecture_variables(template).each do |variable|
                assignment = assignment_value(analysis, variable, before: before)
                barch_arguments = exact_function_call(assignment.fetch('value'), 'barch')
                raise Unsupported, "#{variable} must be assigned by barch" unless barch_arguments&.length == 1

                beacon_expression = barch_arguments.first
                parameter = unwrap_parentheses(beacon_expression).match(PARAMETER_PATTERN)
                if parameter && parameter_modified?(analysis, parameter[0], before: assignment.fetch('offset'))
                  raise Unsupported, "#{parameter[0]} has a dynamic assignment"
                end

                beacon_expression = invocation[parameter[1].to_i - 1] if invocation && parameter && parameter[1].to_i.positive?
                unless beacon_expression && unwrap_parentheses(beacon_expression) == '$1'
                  raise Unsupported, "#{variable} must resolve the alias Beacon architecture"
                end
              end
            end

            def template_parameters(template)
              split_top_level(template, separator: '.').flat_map do |part|
                stripped_part = part.strip
                if stripped_part.start_with?('"')
                  stripped_part.scan(/(?<!\\)\$\d+\b/)
                elsif stripped_part.match?(PARAMETER_PATTERN)
                  stripped_part
                end
              end.compact.uniq
            end

            def architecture_variables(template)
              split_top_level(template, separator: '.').flat_map do |part|
                stripped_part = part.strip
                if stripped_part.start_with?('"')
                  stripped_part.scan(/(?<!\\)\$(?:barch|arch)\b/)
                elsif %w[$barch $arch].include?(stripped_part)
                  stripped_part
                end
              end.compact.uniq
            end

            def variable_assignments(code)
              result = Hash.new { |hash, key| hash[key] = [] }
              masked_code = mask_string_literals(code)
              offset = 0
              pattern = %r{(\$(?:[a-zA-Z_]\w*|\d+))\s*(=(?!=|~|>)|(?:\.|\+|-|\*|/|%|&|\||\^|<<|>>)=|\+\+|--)}
              while (match = pattern.match(masked_code, offset))
                unless match[2] == '=' && top_level_offset?(masked_code, match.begin(0))
                  result[match[1]] << { 'value' => NULL, 'offset' => match.begin(0) }
                  offset = match.end(0)
                  next
                end

                terminator = matching_terminator(masked_code, match.end(0), ';')
                break unless terminator

                result[match[1]] << { 'value' => code[match.end(0)...terminator].strip, 'offset' => match.begin(0) }
                offset = terminator + 1
              end
              record_dynamic_assignments!(result, masked_code, /\(([^()]*)\)\s*=(?!=|~|>)/m)
              record_dynamic_assignments!(result, masked_code, /\bwhile\s+(\$(?:[a-zA-Z_]\w*|\d+))\s*\(/)
              record_dynamic_assignments!(result, masked_code, /\bforeach\s+([^(){};]+)\s*\(/m)
              record_dynamic_assignments!(result, masked_code, /\bcatch\s+(\$(?:[a-zA-Z_]\w*|\d+))\s*\{/)
              result
            end

            def record_dynamic_assignments!(assignments, code, pattern)
              offset = 0
              while (match = pattern.match(code, offset))
                match[1].scan(/\$(?:[a-zA-Z_]\w*|\d+)\b/) do |variable|
                  assignments[variable] << { 'value' => NULL, 'offset' => match.begin(0) }
                end
                offset = match.end(0)
              end
            end

            def code_analysis(code)
              assignments = variable_assignments(code)
              scope_writes = variable_scope_writes(code)
              {
                'assignments' => assignments,
                'parameter_writes' => parameter_writes(code, assignments, scope_writes),
                'scope_writes' => scope_writes
              }
            end

            def variable_scope_writes(code)
              writes = Hash.new { |hash, key| hash[key] = [] }
              %w[global local this].each do |declaration|
                function_calls(code, declaration).zip(function_call_offsets(code, declaration)).each do |arguments, call_offset|
                  arguments.each do |argument|
                    argument.scan(/\$(?:[a-zA-Z_]\w*|\d+)\b/) { |variable| writes[variable] << call_offset } if string_literal?(argument.strip)
                  end
                end
              end
              writes
            end

            def parameter_writes(code, assignments, scope_writes)
              masked_code = mask_string_literals(code)
              writes = Hash.new { |hash, key| hash[key] = [] }
              assignments.each do |parameter, candidates|
                writes[parameter].concat(candidates.map { |candidate| candidate.fetch('offset') }) if parameter.match?(PARAMETER_PATTERN)
              end
              scope_writes.each do |parameter, offsets|
                writes[parameter].concat(offsets) if parameter.match?(PARAMETER_PATTERN)
              end

              record_argument_array_writes!(writes, masked_code)

              writes
            end

            def record_argument_array_writes!(writes, code)
              pattern = %r{@_\s*\[([^\]]+)\]\s*(?:=(?!=|~|>)|(?:\.|\+|-|\*|/|%|&|\||\^|<<|>>)=|\+\+|--)}
              code.to_enum(:scan, pattern).each do
                offset = ::Regexp.last_match.begin(0)
                index = ::Regexp.last_match(1).strip
                if index.match?(/\A\d+\z/)
                  writes["$#{index.to_i + 1}"] << offset
                else
                  writes['*'] << offset
                end
              end

              code.to_enum(:scan, /\(([^()]*)\)\s*=(?!=|~|>)/m).each do
                writes['*'] << ::Regexp.last_match.begin(0) if ::Regexp.last_match(1).match?(/@_\s*\[/)
              end

              code.to_enum(:scan, /\bforeach\s+([^(){};]+)\s*\(([^()]*)\)\s*\{/m).each do
                foreach_match = ::Regexp.last_match
                next unless foreach_match[2].match?(/@_\b/)

                value_variable = foreach_match[1].split('=>').last.strip
                next unless value_variable.match?(VARIABLE_PATTERN)

                opening = foreach_match.end(0) - 1
                closing = matching_delimiter(code, opening, '{', '}')
                next unless closing

                loop_body = code[(opening + 1)...closing]
                direct_write = variable_assignments(loop_body).key?(value_variable)
                tuple_write = loop_body.scan(/\(([^()]*)\)\s*=(?!=|~|>)/m).any? do |group|
                  group.first.scan(/\$[a-zA-Z_]\w*/).include?(value_variable)
                end
                writes['*'] << foreach_match.begin(0) if direct_write || tuple_write
              end
            end

            def record_parameter_writes!(writes, code, pattern)
              offset = 0
              while (match = pattern.match(code, offset))
                match[1].scan(/\$\d+\b/) { |parameter| writes[parameter] << match.begin(0) }
                offset = match.end(0)
              end
            end

            def named_blocks(keyword)
              blocks = []
              masked_code = mask_string_literals(@code)
              offset = 0
              pattern = /\b#{keyword}\s+([a-zA-Z_][a-zA-Z0-9_-]*)\s*\{/
              while (match = pattern.match(masked_code, offset))
                unless top_level_offset?(masked_code, match.begin(0))
                  offset = match.end(0)
                  next
                end

                opening = masked_code.index('{', match.begin(0))
                closing = matching_delimiter(masked_code, opening, '{', '}')
                break unless closing

                blocks << [match[1], @code[(opening + 1)...closing]]
                offset = closing + 1
              end
              blocks
            end

            def declared_block_names(keyword)
              mask_string_literals(@code).scan(/\b#{Regexp.escape(keyword)}\s+([a-zA-Z_][a-zA-Z0-9_-]*)\s*\{/).flatten.uniq
            end

            def validate_required_intrinsics!(code)
              used_overrides = @overridden_intrinsics.select { |name| function_calls(code, name).any? }
              raise Unsupported, "overrides required functions: #{used_overrides.sort.join(', ')}" unless used_overrides.empty?
            end

            def validate_required_intrinsic!(name)
              raise Unsupported, "overrides required functions: #{name}" if @overridden_intrinsics.include?(name)
            end

            def function_calls(code, function_name, top_level: false)
              calls = []
              delimiters = { '(' => ')', '[' => ']', '{' => '}' }
              stack = []
              quote = nil
              escaped = false
              pattern = /(?<![a-zA-Z0-9_])&?#{Regexp.escape(function_name)}\s*\(/
              index = 0
              statement_start = 0

              while index < code.length
                character = code[index]
                if quote
                  if escaped
                    escaped = false
                  elsif character == '\\'
                    escaped = true
                  elsif character == quote
                    quote = nil
                  end
                elsif ["'", '"'].include?(character)
                  quote = character
                elsif delimiters.key?(character)
                  stack << delimiters.fetch(character)
                elsif stack.last == character
                  stack.pop
                  statement_start = index + 1 if top_level && stack.empty? && character == '}'
                elsif character == ';' && stack.empty?
                  statement_start = index + 1
                elsif !top_level || stack.empty?
                  match = pattern.match(code, index)
                  if match&.begin(0) == index
                    opening = code.index('(', index)
                    closing = matching_delimiter(code, opening, '(', ')')
                    break unless closing

                    following_character = code[(closing + 1)..]&.match(/\S/)&.[](0)
                    direct_call = code[statement_start...index].strip.empty? && [nil, ';'].include?(following_character)
                    calls << split_top_level(code[(opening + 1)...closing]) if !top_level || direct_call
                    index = closing
                  end
                end
                index += 1
              end
              calls
            end

            def flow_control_exit_before_call?(code, function_name)
              control_keyword_before?(code, function_call_offset(code, function_name), %w[return throw])
            end

            def assertion_before_call?(code, function_name)
              control_keyword_before?(code, function_call_offset(code, function_name), ['assert'])
            end

            def control_keyword_before?(code, offset, keywords)
              return false unless offset

              masked_code = mask_string_literals(code)
              keywords.any? { |keyword| statement_keyword_offsets(masked_code, keyword).any? { |keyword_offset| keyword_offset < offset } }
            end

            def function_call_offset(code, function_name)
              function_call_offsets(code, function_name).first
            end

            def function_call_offsets(code, function_name)
              offsets = []
              mask_string_literals(code).scan(/(?<![a-zA-Z0-9_])&?#{Regexp.escape(function_name)}\s*\(/) do
                offsets << ::Regexp.last_match.begin(0)
              end
              offsets
            end

            def keyword_offset(code, keyword)
              statement_keyword_offsets(mask_string_literals(code), keyword).first
            end

            def statement_keyword_offsets(masked_code, keyword)
              offsets = []
              masked_code.to_enum(:scan, /(?<![a-zA-Z0-9_$%@&.-])#{Regexp.escape(keyword)}(?![a-zA-Z0-9_-])/).each do
                offset = ::Regexp.last_match.begin(0)
                offsets << offset if statement_keyword_at?(masked_code, offset, keyword)
              end
              offsets
            end

            def statement_keyword_at?(masked_code, offset, keyword)
              return false unless masked_code[offset, keyword.length] == keyword
              return false if offset.positive? && masked_code[offset - 1].match?(/[a-zA-Z0-9_$%@&.-]/)
              return false if masked_code[offset + keyword.length].to_s.match?(/[a-zA-Z0-9_-]/)

              previous_character = masked_code[0...offset].rstrip[-1]
              previous_character.nil? || [';', '{', '}'].include?(previous_character)
            end

            def unmodified_parameter?(expression, analysis, expected, before:)
              parameter = unwrap_parentheses(expression).match(PARAMETER_PATTERN)
              parameter && parameter[0] == expected && !parameter_modified?(analysis, parameter[0], before: before)
            end

            def exact_function_call(code, function_name)
              expression = unwrap_parentheses(code)
              match = /\A&?#{Regexp.escape(function_name)}\s*\(/.match(expression)
              return unless match

              opening = expression.index('(', match.begin(0))
              closing = matching_delimiter(expression, opening, '(', ')')
              return unless closing == expression.length - 1

              split_top_level(expression[(opening + 1)...closing])
            end

            def split_top_level(code, separator: ',')
              values = []
              start = 0
              delimiters = { '(' => ')', '[' => ']', '{' => '}' }
              stack = []
              quote = nil
              escaped = false
              code.each_char.with_index do |character, index|
                if quote
                  if escaped
                    escaped = false
                  elsif character == '\\'
                    escaped = true
                  elsif character == quote
                    quote = nil
                  end
                  next
                end

                if ["'", '"'].include?(character)
                  quote = character
                elsif delimiters.key?(character)
                  stack << delimiters.fetch(character)
                elsif stack.last == character
                  stack.pop
                elsif character == separator && stack.empty?
                  values << code[start...index].strip
                  start = index + 1
                end
              end
              values << code[start..].strip
              values
            end

            def matching_delimiter(code, opening, left, right)
              depth = 0
              quote = nil
              escaped = false
              code.each_char.with_index do |character, index|
                next if index < opening

                if quote
                  if escaped
                    escaped = false
                  elsif character == '\\'
                    escaped = true
                  elsif character == quote
                    quote = nil
                  end
                  next
                end

                if ["'", '"'].include?(character)
                  quote = character
                elsif character == left
                  depth += 1
                elsif character == right
                  depth -= 1
                  return index if depth.zero?
                end
              end
              nil
            end

            def matching_terminator(code, offset, terminator)
              delimiters = { '(' => ')', '[' => ']', '{' => '}' }
              stack = []
              quote = nil
              escaped = false
              code.each_char.with_index do |character, index|
                next if index < offset

                if quote
                  if escaped
                    escaped = false
                  elsif character == '\\'
                    escaped = true
                  elsif character == quote
                    quote = nil
                  end
                  next
                end

                if ["'", '"'].include?(character)
                  quote = character
                elsif delimiters.key?(character)
                  stack << delimiters.fetch(character)
                elsif stack.last == character
                  stack.pop
                elsif character == terminator && stack.empty?
                  return index
                end
              end
              nil
            end

            def top_level_offset?(code, offset)
              delimiters = { '(' => ')', '[' => ']', '{' => '}' }
              stack = []
              quote = nil
              escaped = false
              code.each_char.with_index do |character, index|
                break if index == offset

                if quote
                  if escaped
                    escaped = false
                  elsif character == '\\'
                    escaped = true
                  elsif character == quote
                    quote = nil
                  end
                elsif ["'", '"'].include?(character)
                  quote = character
                elsif delimiters.key?(character)
                  stack << delimiters.fetch(character)
                elsif stack.last == character
                  stack.pop
                end
              end
              stack.empty?
            end

            def assignment_value(analysis, variable, before:)
              candidates = analysis.fetch('assignments')[variable]&.select { |candidate| candidate.fetch('offset') < before }
              unless candidates&.length == 1 && candidates.first.fetch('value').is_a?(String)
                raise Unsupported, "#{variable} has a dynamic assignment"
              end

              scope_changed = analysis.fetch('scope_writes')[variable]&.any? do |offset|
                offset.between?(candidates.first.fetch('offset'), before - 1)
              end

              raise Unsupported, "#{variable} has a dynamic assignment" if scope_changed

              candidates.first
            end

            def parameter_modified?(analysis, parameter, before:)
              writes = analysis.fetch('parameter_writes')
              writes[parameter]&.any? { |offset| offset < before } || writes['*']&.any? { |offset| offset < before }
            end

            def mask_string_literals(code)
              quote = nil
              escaped = false
              code.each_char.map do |character|
                if quote
                  if escaped
                    escaped = false
                  elsif character == '\\'
                    escaped = true
                  elsif character == quote
                    quote = nil
                  end
                  next character == "\n" ? character : ' '
                end
                if ["'", '"'].include?(character)
                  quote = character
                  next ' '
                end

                character
              end.join
            end

            def remove_comments(source)
              quote = nil
              escaped = false
              comment = false
              source.each_char.map do |character|
                if comment
                  comment = false if character == "\n"
                  next character if character == "\n"

                  next ' '
                end
                if quote
                  if escaped
                    escaped = false
                  elsif character == '\\'
                    escaped = true
                  elsif character == quote
                    quote = nil
                  end
                  next character
                end
                if ["'", '"'].include?(character)
                  quote = character
                  next character
                end
                if character == '#'
                  comment = true
                  next ' '
                end

                character
              end.join
            end

            def literal(expression, binary: false)
              return NULL unless expression

              value = expression.strip
              return nil if value == '$null'
              return parse_string(value, binary: binary) if string_literal?(value) && !interpolated_string?(value)
              return Integer(value, 0) if value.match?(/\A-?(?:0x[0-9a-fA-F]+|0[0-7]*|[1-9]\d*)\z/)

              NULL
            end

            def string_literal?(value)
              value.match?(/\A"(?:\\.|[^"\\])*"\z/m) || value.match?(/\A'(?:\\.|[^'\\])*'\z/m)
            end

            def interpolated_string?(value)
              return false unless value.start_with?('"')

              escaped = false
              value[1...-1].each_char do |character|
                if escaped
                  escaped = false
                elsif character == '\\'
                  escaped = true
                elsif character == '$'
                  return true
                end
              end
              false
            end

            def parse_string(value, binary: false)
              content = value[1...-1]
              return content.gsub(/\\([\\'])/) { ::Regexp.last_match(1) } if value.start_with?("'")

              content = content.b if binary
              content = content.gsub(/\\u(d[89ab][0-9a-f]{2})\\u(d[c-f][0-9a-f]{2})/i) do
                high_surrogate = ::Regexp.last_match(1).to_i(16)
                low_surrogate = ::Regexp.last_match(2).to_i(16)
                codepoint = 0x10000 + ((high_surrogate - 0xd800) << 10) + low_surrogate - 0xdc00
                character = codepoint.chr(::Encoding::UTF_8)
                binary ? character.b : character
              end

              content.gsub(/\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|(.))/m) do
                byte_escape = ::Regexp.last_match(1)
                unicode_escape = ::Regexp.last_match(2)
                character = ::Regexp.last_match(3) unless byte_escape || unicode_escape

                next byte_escape.to_i(16).chr if binary && byte_escape
                next byte_escape.to_i(16).chr(::Encoding::UTF_8) if byte_escape
                next unicode_escape.to_i(16).chr(::Encoding::UTF_8) if unicode_escape

                { 'n' => "\n", 'r' => "\r", 't' => "\t" }.fetch(character, character)
              end
            rescue RangeError
              raise Unsupported, 'string contains an unsupported Unicode surrogate escape'
            end
          end
        end
      end
    end
  end
end
