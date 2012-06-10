module Treetop
  module Compiler    
    class ParenthesizedExpression < ParsingExpression
      def compile(address, builder, parent_expression = nil)
        elements[2].compile(address, builder, parent_expression)
      end
    end
  end
end