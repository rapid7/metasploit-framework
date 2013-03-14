module Treetop
  module Compiler    
    class AnythingSymbol < AtomicExpression
      def compile(address, builder, parent_expression = nil)
        super
        builder.if__ "index < input_length" do
          assign_result "instantiate_node(#{node_class_name},input, index...(index + 1))"
          extend_result_with_inline_module
          builder << "@index += 1"
        end
        builder.else_ do
          builder << 'terminal_parse_failure("any character")'
          assign_result 'nil'
        end
      end
    end
  end
end