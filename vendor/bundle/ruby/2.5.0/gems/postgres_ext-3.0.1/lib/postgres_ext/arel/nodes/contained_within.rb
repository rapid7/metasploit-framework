require 'arel/nodes/binary'
module Arel
  module Nodes
    class ContainedWithin < Arel::Nodes::Binary
      def operator; :<< end
    end

    class ContainedWithinEquals < Arel::Nodes::Binary
      def operator; :"<<=" end
    end

    class Contains < Arel::Nodes::Binary
      def operator; :>> end
    end

    class ContainsINet < Arel::Nodes::Binary
      def operator; :>> end
    end

    class ContainsHStore < Arel::Nodes::Binary
      def operator; :"@>" end
    end

    class ContainedInHStore < Arel::Nodes::Binary
      def operator; :"<@" end
    end

    class ContainsArray < Arel::Nodes::Binary
      def operator; :"@>" end
    end

    class ContainedInArray < Arel::Nodes::Binary
      def operator; :"<@" end
    end

    class ContainsEquals < Arel::Nodes::Binary
      def operator; :">>=" end
    end
  end
end
