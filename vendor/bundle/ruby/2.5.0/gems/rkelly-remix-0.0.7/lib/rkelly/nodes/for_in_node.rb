module RKelly
  module Nodes
    class ForInNode < Node
      attr_reader :left, :right
      def initialize(left, right, block)
        super(block)
        @left = left
        @right = right
      end
    end
  end
end
