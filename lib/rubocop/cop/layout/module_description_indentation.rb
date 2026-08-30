module RuboCop
  module Cop
    module Layout
      class ModuleDescriptionIndentation < Base
        extend AutoCorrector
        include Alignment

        MSG = "Module descriptions should be properly aligned to the 'Description' key, and within %q{ ... }"

        def_node_matcher :find_update_info_node, <<~PATTERN
          (def :initialize _args (begin (super $(send nil? {:update_info :merge_info} (lvar :info) (hash ...))) ...))
        PATTERN

        def_node_matcher :find_nested_update_info_node, <<~PATTERN
          (def :initialize _args (super $(send nil? {:update_info :merge_info} (lvar :info) (hash ...)) ...))
        PATTERN

        def on_def(node)
          update_info_node = find_update_info_node(node) || find_nested_update_info_node(node)
          return if update_info_node.nil?

          hash = update_info_node.arguments.find { |argument| hash_arg?(argument) }
          hash.each_pair do |key, value|
            if key.value == "Description"
              if requires_correction?(key, value)
                add_offense(value.location.end, &autocorrector(value))
              end
            end
          end
        end

        private

        def autocorrector(description_value)
          lambda do |corrector|
            description_key = description_value.parent.key
            new_content = indent_description_value_correctly(description_key, description_value)

            corrector.replace(description_value.source_range, new_content)
          end
        end

        def requires_correction?(description_key, description_value)
          return false if description_value.single_line?

          current_content = description_value.source
          expected_content = indent_description_value_correctly(description_key, description_value)
          expected_content != current_content
        end

        def indent_description_value_correctly(description_key, description_value)
          content_whitespace = indentation(description_key)
          final_line_whitespace = offset(description_key)

          description_lines = node_content(description_value).strip.lines
          indented_description = description_lines.map do |line|
            cleaned_content = line.strip
            if cleaned_content.empty?
              "\n"
            else
              "#{content_whitespace}#{cleaned_content}\n"
            end
          end.join

          new_literal = "%q{\n"
          new_literal <<= indented_description
          new_literal <<= final_line_whitespace
          new_literal <<= '}'

          new_literal
        end

        def node_content(node)
          if node.str_type?
            node.value
          elsif node.dstr_type?
            node.children.map(&:value).join
          else
            raise "Module description should be a string, instead found '#{node.type}'"
          end
        end

        def hash_arg?(node)
          node.type == :hash
        end
      end
    end
  end
end
