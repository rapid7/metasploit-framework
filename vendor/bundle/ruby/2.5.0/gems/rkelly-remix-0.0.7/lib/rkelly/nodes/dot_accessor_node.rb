module RKelly
  module Nodes
    class DotAccessorNode < Node
      attr_reader :accessor
      def initialize(resolve, accessor)
        super(resolve)
        @accessor = accessor
      end
    end
  end
end
