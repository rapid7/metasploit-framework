require 'arel/nodes/binary'

module Arel
  module Nodes
    class Overlap < Arel::Nodes::Binary
      def operator; '&&' end
    end
  end
end
