module RKelly
  module Nodes
    class PostfixNode < Node
      attr_reader :operand
      def initialize(operand, operator)
        super(operator)
        @operand = operand
      end
    end
  end
end
