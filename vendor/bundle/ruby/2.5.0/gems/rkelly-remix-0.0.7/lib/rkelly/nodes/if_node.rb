module RKelly
  module Nodes
    class IfNode < Node
      attr_reader :conditions, :else
      def initialize(conditions, value, else_stmt = nil)
        super(value)
        @conditions = conditions
        @else = else_stmt
      end
    end
  end
end
