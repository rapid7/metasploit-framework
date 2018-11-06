module RKelly
  module Nodes
    class TryNode < Node
      attr_reader :catch_var, :catch_block, :finally_block
      def initialize(value, catch_var, catch_block, finally_block = nil)
        super(value)
        @catch_var = catch_var
        @catch_block = catch_block
        @finally_block = finally_block
      end
    end
  end
end
