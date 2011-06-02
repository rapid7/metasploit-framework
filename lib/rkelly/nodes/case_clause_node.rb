require 'rkelly/nodes/binary_node'

module RKelly
  module Nodes
    class CaseClauseNode < BinaryNode
      def initialize(left, src = SourceElementsNode.new([]))
        super
      end
    end
  end
end
