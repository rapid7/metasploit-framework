module Treetop
  module Compiler    
    class CharacterClass < AtomicExpression
      def compile(address, builder, parent_expression = nil)
        super
        
        builder.if__ "has_terminal?(#{grounded_regexp(text_value)}, true, index)" do
          if address == 0 || decorated?
            assign_result "instantiate_node(#{node_class_name},input, index...(index + 1))"
            extend_result_with_inline_module
          else
            assign_lazily_instantiated_node
          end
          builder << "@index += 1"
        end
        builder.else_ do
          # "terminal_parse_failure(#{single_quote(characters)})"
          assign_result 'nil'
        end
      end

      def grounded_regexp(string)
        # Double any backslashes, then backslash any single-quotes:
        "'\\G#{string.gsub(/\\/) { '\\\\' }.gsub(/'/) { "\\'"}}'"
      end
    end
  end
end
