module RKelly
  module Nodes
    class BinaryNode < Node
      attr_reader :left
      def initialize(left, right)
        super(right)
        @left = left
      end
    end

    %w[Subtract LessOrEqual GreaterOrEqual Add Multiply NotEqual
       DoWhile Switch LogicalAnd UnsignedRightShift Modulus While
       NotStrictEqual Less With In Greater BitOr StrictEqual LogicalOr
       BitXOr LeftShift Equal BitAnd InstanceOf Divide RightShift].each do |node|
      const_set "#{node}Node", Class.new(BinaryNode)
    end
  end
end
