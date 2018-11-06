module RKelly
  module Nodes
    class VarDeclNode < Node
      attr_accessor :name, :type
      def initialize(name, value, constant = false)
        super(value)
        @name = name
        @constant = constant
      end

      def constant?; @constant; end
      def variable?; !@constant; end
    end
  end
end
