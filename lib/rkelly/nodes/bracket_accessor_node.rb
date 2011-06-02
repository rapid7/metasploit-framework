module RKelly
  module Nodes
    class BracketAccessorNode < Node
      attr_reader :accessor
      def initialize(resolve, accessor)
        super(resolve)
        @accessor = accessor
      end
    end
  end
end
