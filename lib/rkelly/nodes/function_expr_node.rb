module RKelly
  module Nodes
    class FunctionExprNode < Node
      attr_reader :function_body, :arguments
      def initialize(name, body, args = [])
        super(name)
        @function_body = body
        @arguments = args
      end
    end
  end
end
