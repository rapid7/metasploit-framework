module RSpec
  module Core
    module Formatters
      # @private
      class SnippetExtractor
        NoSuchFileError = Class.new(StandardError)
        NoSuchLineError = Class.new(StandardError)

        def self.extract_line_at(file_path, line_number)
          source = source_from_file(file_path)
          line = source.lines[line_number - 1]
          raise NoSuchLineError unless line
          line
        end

        def self.source_from_file(path)
          raise NoSuchFileError unless File.exist?(path)
          RSpec.world.source_from_file(path)
        end

        if RSpec::Support::RubyFeatures.ripper_supported?
          NoExpressionAtLineError = Class.new(StandardError)

          attr_reader :source, :beginning_line_number, :max_line_count

          def self.extract_expression_lines_at(file_path, beginning_line_number, max_line_count=nil)
            if max_line_count == 1
              [extract_line_at(file_path, beginning_line_number)]
            else
              source = source_from_file(file_path)
              new(source, beginning_line_number, max_line_count).expression_lines
            end
          end

          def initialize(source, beginning_line_number, max_line_count=nil)
            @source = source
            @beginning_line_number = beginning_line_number
            @max_line_count = max_line_count
          end

          def expression_lines
            line_range = line_range_of_expression

            if max_line_count && line_range.count > max_line_count
              line_range = (line_range.begin)..(line_range.begin + max_line_count - 1)
            end

            source.lines[(line_range.begin - 1)..(line_range.end - 1)]
          rescue SyntaxError, NoExpressionAtLineError
            [self.class.extract_line_at(source.path, beginning_line_number)]
          end

          private

          def line_range_of_expression
            @line_range_of_expression ||= begin
              line_range = line_range_of_location_nodes_in_expression
              initial_unclosed_tokens = unclosed_tokens_in_line_range(line_range)
              unclosed_tokens = initial_unclosed_tokens

              until (initial_unclosed_tokens & unclosed_tokens).empty?
                line_range = (line_range.begin)..(line_range.end + 1)
                unclosed_tokens = unclosed_tokens_in_line_range(line_range)
              end

              line_range
            end
          end

          def unclosed_tokens_in_line_range(line_range)
            tokens = FlatMap.flat_map(line_range) do |line_number|
              source.tokens_by_line_number[line_number]
            end

            tokens.each_with_object([]) do |token, unclosed_tokens|
              if token.opening?
                unclosed_tokens << token
              else
                index = unclosed_tokens.rindex do |unclosed_token|
                  unclosed_token.closed_by?(token)
                end
                unclosed_tokens.delete_at(index) if index
              end
            end
          end

          def line_range_of_location_nodes_in_expression
            line_numbers = expression_node.each_with_object(Set.new) do |node, set|
              set << node.location.line if node.location
            end

            line_numbers.min..line_numbers.max
          end

          def expression_node
            raise NoExpressionAtLineError if location_nodes_at_beginning_line.empty?

            @expression_node ||= begin
              common_ancestor_nodes = location_nodes_at_beginning_line.map do |node|
                node.each_ancestor.to_a
              end.reduce(:&)

              common_ancestor_nodes.find { |node| expression_outmost_node?(node) }
            end
          end

          def expression_outmost_node?(node)
            return true unless node.parent
            return false if node.type.to_s.start_with?('@')
            ![node, node.parent].all? do |n|
              # See `Ripper::PARSER_EVENTS` for the complete list of sexp types.
              type = n.type.to_s
              type.end_with?('call') || type.start_with?('method_add_')
            end
          end

          def location_nodes_at_beginning_line
            source.nodes_by_line_number[beginning_line_number]
          end
        else
          # :nocov:
          def self.extract_expression_lines_at(file_path, beginning_line_number, *)
            [extract_line_at(file_path, beginning_line_number)]
          end
          # :nocov:
        end

        def self.least_indentation_from(lines)
          lines.map { |line| line[/^[ \t]*/] }.min
        end
      end
    end
  end
end
