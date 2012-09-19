module Treetop
  module Compiler
    class Predicate < ParsingExpression
      def compile(address, builder, parent_expression)
        super
        begin_comment(parent_expression)
        use_vars :result, :start_index
        obtain_new_subexpression_address
        parent_expression.prefixed_expression.compile(subexpression_address, builder)
        builder.if__(subexpression_success?) { when_success }
        builder.else_ { when_failure }
        end_comment(parent_expression)
      end
      
      def assign_failure
        super(start_index_var)
      end
      
      def assign_success
        reset_index
        assign_result epsilon_node
      end
    end
    
    class AndPredicate < Predicate
      def when_success
        assign_success
      end

      def when_failure
        assign_failure
      end
    end
    
    class NotPredicate < Predicate
      def when_success
        assign_failure
      end
      
      def when_failure
        assign_success
      end
    end
  end
end