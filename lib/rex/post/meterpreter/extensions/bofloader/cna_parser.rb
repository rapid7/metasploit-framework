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
              'b' => 'file',
              'i' => 'int32',
              's' => 'int16',
              'z' => 'string',
              'Z' => 'wstring'
            }.freeze
            NULL = Object.new.freeze
            PARAMETER_PATTERN = /\A\$(\d+)\z/
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
              aliases = named_blocks('alias')
              registrations = command_registrations
              bofs = {}
              warnings = []

              aliases.each do |alias_name, body|
                next if function_calls(body, 'beacon_inline_execute').empty?

                begin
                  definition = import_alias(alias_name, body, registrations[alias_name])
                  if bofs.key?(alias_name)
                    warnings << "CNA alias '#{alias_name}' is declared more than once"
                  else
                    bofs[alias_name] = definition
                  end
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
              source = ::File.binread(@path).force_encoding(Encoding::UTF_8)
              raise Error, "CNA script is not valid UTF-8: #{@path}" unless source.valid_encoding?

              source
            rescue SystemCallError => e
              raise Error, "Unable to read CNA script #{@path}: #{e.message}"
            end

            def import_alias(alias_name, body, registration)
              execute_calls = function_calls(body, 'beacon_inline_execute')
              raise Unsupported, 'multiple beacon_inline_execute calls are not statically supported' unless execute_calls.length == 1

              execute_arguments = execute_calls.first
              raise Unsupported, 'beacon_inline_execute does not specify a BOF and entry point' if execute_arguments.length < 3

              template, replacements = bof_template(body, execute_arguments[1])
              files = bof_files(template, replacements)
              entry = literal(execute_arguments[2])
              raise Unsupported, 'the BOF entry point is dynamic' unless entry.is_a?(String) && !entry.empty?

              usage = registration && registration['usage']
              packed_arguments = packed_arguments(body, execute_arguments[3])
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
              function_calls(@code, 'beacon_command_register').each_with_object({}) do |arguments, result|
                name = literal(arguments[0])
                description = literal(arguments[1])
                next unless name.is_a?(String) && !name.empty? && description.is_a?(String) && !description.empty?

                usage = literal(arguments[2])
                result[name] = {
                  'description' => description,
                  'usage' => usage.is_a?(String) && !usage.empty? ? usage : name
                }
              end
            end

            def packed_arguments(body, argument_expression)
              return [] if argument_expression.nil? || literal(argument_expression).nil?

              expression = argument_expression.strip
              if expression.match?(VARIABLE_PATTERN)
                assignments = variable_assignments(body)[expression]
                raise Unsupported, "#{expression} has a dynamic assignment" unless assignments&.length == 1

                expression = assignments.first
              end

              calls = function_calls(expression, 'bof_pack')
              raise Unsupported, 'arguments are not assigned by one bof_pack call' unless calls.length == 1

              pack_arguments = calls.first
              format = literal(pack_arguments[1])
              unless format.is_a?(String) && !format.empty? && format.match?(/\A[biszZ]+\z/)
                raise Unsupported, 'bof_pack uses a dynamic or invalid format'
              end
              if pack_arguments.length != format.length + 2
                raise Unsupported, 'bof_pack format and argument counts do not match'
              end

              assignments = variable_assignments(body)
              definitions = format.chars.zip(pack_arguments.drop(2)).map do |format_character, value_expression|
                packed_value(format_character, value_expression, assignments, [])
              end
              positions = definitions.filter_map { |definition| definition['position'] }.uniq.sort
              if positions.any? && positions != (0..positions.max).to_a
                raise Unsupported, 'CNA positional arguments are transformed outside bof_pack'
              end

              definitions
            end

            def packed_value(format_character, expression, assignments, seen)
              value = literal(expression)
              unless value.equal?(NULL)
                fixed = value.nil? && format_character == 'b' ? String.new.b : value
                raise Unsupported, "#{format_character} argument has an incompatible literal" unless compatible_literal?(format_character, fixed)

                return packed_definition(format_character).merge('fixed' => fixed)
              end

              if (match = expression.strip.match(PARAMETER_PATTERN))
                position = match[1].to_i - 2
                raise Unsupported, 'Beacon ID cannot be used as a BOF argument' if position.negative?

                return packed_definition(format_character).merge('position' => position, 'required' => true)
              end

              variable = expression.strip
              if variable.match?(VARIABLE_PATTERN)
                raise Unsupported, "recursive assignment for #{variable}" if seen.include?(variable)

                candidates = assignments[variable]
                raise Unsupported, "#{variable} has a dynamic assignment" unless candidates&.length == 1

                return packed_value(format_character, candidates.first, assignments, seen + [variable])
              end

              if format_character == 'b'
                position = file_position(expression, assignments, seen)
                return packed_definition(format_character).merge('type' => 'file', 'raw' => false, 'position' => position, 'required' => true)
              end

              optional_value(format_character, expression, assignments, seen) || raise(
                Unsupported,
                "cannot statically evaluate packed expression #{expression.strip}"
              )
            end

            def optional_value(format_character, expression, assignments, seen)
              calls = function_calls(expression, 'iff')
              return unless calls.length == 1 && calls.first.length == 3

              condition, true_expression, false_expression = calls.first
              match = condition.strip.match(/\A-istrue\s+(\$\d+)\z/)
              return unless match && true_expression.strip == match[1]

              default = literal(false_expression)
              return if default.equal?(NULL) || !compatible_literal?(format_character, default)

              packed_value(format_character, match[1], assignments, seen).merge('required' => false, 'default' => default)
            end

            def file_position(expression, assignments, seen)
              variable = expression.strip
              if (match = variable.match(PARAMETER_PATTERN))
                position = match[1].to_i - 2
                raise Unsupported, 'Beacon ID cannot identify a local file' if position.negative?

                return position
              end

              if variable.match?(VARIABLE_PATTERN)
                raise Unsupported, "recursive assignment for #{variable}" if seen.include?(variable)

                candidates = assignments[variable]
                raise Unsupported, "#{variable} has a dynamic assignment" unless candidates&.length == 1

                return file_position(candidates.first, assignments, seen + [variable])
              end

              %w[readb openf].each do |function_name|
                calls = function_calls(expression, function_name)
                return file_position(calls.first.first, assignments, seen) if calls.length == 1
              end

              raise Unsupported, "cannot determine the local file for packed expression #{expression.strip}"
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
                value.is_a?(Integer)
              when 'z', 'Z'
                value.is_a?(String)
              end
            end

            def decorate_arguments!(definitions, usage)
              argument_names = usage_argument_names(usage)
              used_names = {}
              definitions.each do |definition|
                next if definition.key?('fixed')

                position = definition['position']
                base_name = argument_names[position] || "argument_#{position + 1}"
                name = unique_name(base_name, used_names)
                definition['name'] = name
                definition['description'] = "CNA positional argument #{position + 1}"
              end
            end

            def usage_argument_names(usage)
              return [] unless usage

              usage.scan(/<([^>]+)>|\[([^\]]+)\]/).map do |angle, square|
                description = angle || square
                description = description.sub(/\A(?:optional|required|opt)\s*:?\s*/i, '')
                candidate = description[/[a-zA-Z][a-zA-Z0-9_-]*/]
                candidate&.downcase&.tr('-', '_')
              end.compact
            end

            def unique_name(base_name, used_names)
              count = used_names[base_name] = used_names.fetch(base_name, 0) + 1
              count == 1 ? base_name : "#{base_name}_#{count}"
            end

            def bof_template(body, data_expression)
              resource = function_calls(body, 'script_resource').find { |arguments| arguments.first&.include?('.o') }
              return [resource.first, {}] if resource

              @subroutines.each do |name, subroutine_body|
                invocation = function_calls(data_expression, name)
                next unless invocation.length == 1

                resource = function_calls(subroutine_body, 'script_resource').find { |arguments| arguments.first&.include?('.o') }
                next unless resource

                replacements = invocation.first.each_with_index.each_with_object({}) do |(argument, index), result|
                  value = literal(argument)
                  result["$#{index + 1}"] = value unless value.equal?(NULL)
                end
                return [resource.first, replacements]
              end

              raise Unsupported, 'cannot determine the BOF path'
            end

            def bof_files(template, replacements)
              architecture_variables = template.scan(/\$[a-zA-Z_]\w*/).select { |variable| variable.match?(/arch\z/i) }
              architecture_variables |= ['$barch', '$arch']
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
                value = literal(part)
                if value.is_a?(String)
                  replacements.reduce(value) { |result, (variable, replacement)| result.gsub(/#{Regexp.escape(variable)}\b/, replacement.to_s) }
                elsif replacements.key?(part.strip)
                  replacements.fetch(part.strip).to_s
                else
                  raise Unsupported, "BOF path contains dynamic expression #{part.strip}"
                end
              end.join
              evaluated.gsub!(/\s*\$\+\s*/, '')
              raise Unsupported, 'BOF path still contains dynamic variables' if evaluated.include?('$')

              ::File.expand_path(evaluated.tr('\\', ::File::SEPARATOR), @base_path)
            end

            def path_architecture(path)
              normalized_path = path.downcase.tr('\\', '/')
              return 'x64' if normalized_path.match?(%r{(?:\A|[._/-])x64(?:[._/-]|\z)})
              return 'x86' if normalized_path.match?(%r{(?:\A|[._/-])x86(?:[._/-]|\z)})
              return unless ::File.file?(path) && ::File.readable?(path)

              machine = ::File.binread(path, 2).unpack1('v')
              { 0x8664 => 'x64', 0x014c => 'x86' }[machine]
            rescue SystemCallError
              nil
            end

            def variable_assignments(code)
              result = Hash.new { |hash, key| hash[key] = [] }
              offset = 0
              pattern = /(\$[a-zA-Z_]\w*)\s*=\s*/
              while (match = pattern.match(code, offset))
                terminator = matching_terminator(code, match.end(0), ';')
                break unless terminator

                result[match[1]] << code[match.end(0)...terminator].strip
                offset = terminator + 1
              end
              result
            end

            def named_blocks(keyword)
              blocks = {}
              offset = 0
              pattern = /\b#{keyword}\s+([a-zA-Z_][a-zA-Z0-9_-]*)\s*\{/
              while (match = pattern.match(@code, offset))
                opening = @code.index('{', match.begin(0))
                closing = matching_delimiter(@code, opening, '{', '}')
                break unless closing

                blocks[match[1]] = @code[(opening + 1)...closing]
                offset = closing + 1
              end
              blocks
            end

            def function_calls(code, function_name)
              calls = []
              offset = 0
              pattern = /(?<![a-zA-Z0-9_])&?#{Regexp.escape(function_name)}\s*\(/
              while (match = pattern.match(code, offset))
                opening = code.index('(', match.begin(0))
                closing = matching_delimiter(code, opening, '(', ')')
                break unless closing

                calls << split_top_level(code[(opening + 1)...closing])
                offset = closing + 1
              end
              calls
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

            def literal(expression)
              return NULL unless expression

              value = expression.strip
              return nil if value == '$null'
              return parse_string(value) if value.match?(/\A(["']).*\1\z/m)
              return Integer(value, 0) if value.match?(/\A-?(?:0x[0-9a-fA-F]+|\d+)\z/)

              NULL
            end

            def parse_string(value)
              value[1...-1].gsub(/\\(?:n|r|t|\\|"|')/) do |escape|
                { '\\n' => "\n", '\\r' => "\r", '\\t' => "\t", '\\\\' => '\\', '\\"' => '"', "\\'" => "'" }.fetch(escape)
              end
            end
          end
        end
      end
    end
  end
end
