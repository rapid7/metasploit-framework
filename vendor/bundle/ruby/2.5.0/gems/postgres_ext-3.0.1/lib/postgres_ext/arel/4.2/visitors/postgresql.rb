require 'arel/visitors/postgresql'

module Arel
  module Visitors
    class PostgreSQL
      private

      def visit_Arel_Nodes_ContainedWithin o, collector
        infix_value o, collector, " << "
      end

      def visit_Arel_Nodes_ContainedWithinEquals o, collector
        infix_value o, collector, " <<= "
      end

      def visit_Arel_Nodes_Contains o, collector
        left_column = o.left.relation.engine.columns.find do |col|
          col.name == o.left.name.to_s || col.name == o.left.relation.name.to_s
        end

        if left_column && (left_column.type == :hstore || (left_column.respond_to?(:array) && left_column.array))
          infix_value o, collector, " @> "
        else
          infix_value o, collector, " >> "
        end
      end

      def visit_Arel_Nodes_ContainsINet o, collector
        infix_value o, collector, " >> "
      end

      def visit_Arel_Nodes_ContainsHStore o, collector
        infix_value o, collector, " @> "
      end

      def visit_Arel_Nodes_ContainedInHStore o, collector
        infix_value o, collector, " <@ "
      end

      def visit_Arel_Nodes_ContainsArray o, collector
        infix_value o, collector, " @> "
      end

      def visit_Arel_Nodes_ContainedInArray o, collector
        infix_value o, collector, " <@ "
      end

      def visit_Arel_Nodes_ContainsEquals o, collector
        infix_value o, collector, " >>= "
      end

      def visit_Arel_Nodes_Overlap o, collector
        infix_value o, collector, " && "
      end

      def visit_IPAddr value, collector
        collector << quote("#{value.to_s}/#{value.instance_variable_get(:@mask_addr).to_s(2).count('1')}")
      end
    end
  end
end
