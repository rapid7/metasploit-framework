module Arithmetic
  class BinaryOperation < Treetop::Runtime::SyntaxNode
    def eval(env={})
      tail.elements.inject(head.eval(env)) do |value, element|
        element.operator.apply(value, element.operand.eval(env))
      end
    end
  end
end
