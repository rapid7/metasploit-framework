module Treetop
  module Compiler
    class PredicateBlock < ParsingExpression
      def compile(index, builder, parent_expression = nil)
        super
        # REVISIT: This is distinctly dodgey, but since we can only be called from
        # two contexts, and it works in both those, I'm going with it for now, as
        # opposed to doing the major refactor of providing a proper way of accessing
        # the parent's accumulator variable.
        p = parent
        p = p.parent while p && !p.respond_to?(:accumulator_var)
        assign_result "lambda #{text_value}.call(#{p ? p.accumulator_var : ""})"
      end
    end
  end
end
