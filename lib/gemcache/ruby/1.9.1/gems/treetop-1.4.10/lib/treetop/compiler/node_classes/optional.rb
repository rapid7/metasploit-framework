module Treetop
  module Compiler
    class Optional < ParsingExpression
      def compile(address, builder, parent_expression)
        super
        use_vars :result
        obtain_new_subexpression_address
        parent_expression.atomic.compile(subexpression_address, builder)
        
        builder.if__ subexpression_success? do
          assign_result subexpression_result_var
        end
        builder.else_ do
          assign_result epsilon_node
        end
      end
    end
  end
end