module Treetop
  module Compiler
    class Repetition < ParsingExpression
      def compile(address, builder, parent_expression)
        super
        repeated_expression = parent_expression.atomic
        begin_comment(parent_expression)
        use_vars :result, :accumulator, :start_index

        builder.loop do
          obtain_new_subexpression_address
          repeated_expression.compile(subexpression_address, builder)
          builder.if__ subexpression_success? do
            accumulate_subexpression_result
          end
          builder.else_ do
            builder.break
          end
          if max && !max.empty?
            builder.if_ "#{accumulator_var}.size == #{max.text_value}" do
              builder.break
            end
          end
        end
      end

      def inline_module_name
        parent_expression.inline_module_name
      end

      def assign_and_extend_result
        assign_result "instantiate_node(#{node_class_name},input, #{start_index_var}...index, #{accumulator_var})"
        extend_result_with_inline_module
      end
    end


    class ZeroOrMore < Repetition
      def compile(address, builder, parent_expression)
        super
        assign_and_extend_result
        end_comment(parent_expression)
      end

      def max
        nil
      end
    end

    class OneOrMore < Repetition
      def compile(address, builder, parent_expression)
        super
        builder.if__ "#{accumulator_var}.empty?" do
          reset_index
          assign_failure start_index_var
        end
        builder.else_ do
          assign_and_extend_result
        end
        end_comment(parent_expression)
      end

      def max
        nil
      end
    end

    class OccurrenceRange < Repetition
      def compile(address, builder, parent_expression)
        super

        if min.empty? || min.text_value.to_i == 0
          assign_and_extend_result
        else
          # We got some, but fewer than we wanted. There'll be a failure reported already
          builder.if__ "#{accumulator_var}.size < #{min.text_value}" do
            reset_index
            assign_failure start_index_var
          end
          builder.else_ do
            assign_and_extend_result
          end
        end
        end_comment(parent_expression)
      end
    end

  end
end
