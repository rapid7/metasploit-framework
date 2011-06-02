module RKelly
  module Nodes
    class BinaryNode < Node
      attr_reader :left
      def initialize(left, right)
        super(right)
        @left = left
      end
    end

    %w[Subtract LessOrEqual GreaterOrEqual Add Multiply While NotEqual
       DoWhile Switch LogicalAnd UnsignedRightShift Modulus While
       NotStrictEqual Less With In Greater BitOr StrictEqual LogicalOr
       BitXOr LeftShift Equal BitAnd InstanceOf Divide RightShift].each do |node|
      eval "class #{node}Node < BinaryNode; end"
    end
  end
end
