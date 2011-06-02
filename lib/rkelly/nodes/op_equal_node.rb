module RKelly
  module Nodes
    class OpEqualNode < Node
      attr_reader :left
      def initialize(left, right)
        super(right)
        @left = left
      end
    end

    %w[Multiply Divide LShift Minus Plus Mod XOr RShift And URShift Or].each do |node|
      eval "class Op#{node}EqualNode < OpEqualNode; end"
    end

  end
end
