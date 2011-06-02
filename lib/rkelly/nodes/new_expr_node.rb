module RKelly
  module Nodes
    class NewExprNode < Node
      attr_reader :arguments
      def initialize(value, args)
        super(value)
        @arguments = args
      end
    end
  end
end
