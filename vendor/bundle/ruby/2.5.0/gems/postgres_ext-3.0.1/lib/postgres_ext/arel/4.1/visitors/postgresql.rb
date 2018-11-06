require 'arel/visitors/postgresql'

module Arel
  module Visitors
    class PostgreSQL
      private

      def visit_Array o, a
        column = case a.try(:relation)
                 when Arel::Nodes::TableAlias, NilClass
                 # noop Prevent from searching for table alias name in schema cache
                 # which won't exist for aliased table when used with Single Table
                 # Inheritance. see dockyard/postgres_ext#154 (This issue has been removed)
                 else
                  cache = a.relation.engine.connection.schema_cache
                  if cache.table_exists? a.relation.name
                    cache.columns(a.relation.name).find { |col| col.name == a.name.to_s }
                  end
                 end

        if column && column.respond_to?(:array) && column.array
          quoted o, a
        else
          o.empty? ? 'NULL' : o.map { |x| visit x }.join(', ')
        end
      end

      def visit_Arel_Nodes_Contains o, a = nil
        left_column = o.left.relation.engine.columns.find { |col| col.name == o.left.name.to_s }

        if left_column && (left_column.type == :hstore || (left_column.respond_to?(:array) && left_column.array))
          "#{visit o.left, a} @> #{visit o.right, o.left}"
        else
          "#{visit o.left, a} >> #{visit o.right, o.left}"
        end
      end

      def visit_Arel_Nodes_ContainedWithin o, a = nil
        "#{visit o.left, a} << #{visit o.right, o.left}"
      end

      def visit_Arel_Nodes_ContainedWithinEquals o, a = nil
        "#{visit o.left, a} <<= #{visit o.right, o.left}"
      end

      def visit_Arel_Nodes_ContainsArray o, a = nil
        "#{visit o.left, a} @> #{visit o.right, o.left}"
      end

      def visit_Arel_Nodes_ContainedInArray o, a = nil
        "#{visit o.left, a} <@ #{visit o.right, o.left}"
      end

      def visit_Arel_Nodes_ContainsHStore o, a = nil
        "#{visit o.left, a} @> #{visit o.right, o.left}"
      end

      def visit_Arel_Nodes_ContainedInHStore o, a = nil
        "#{visit o.left, a} <@ #{visit o.right, o.left}"
      end

      def visit_Arel_Nodes_ContainsINet o, a = nil
        "#{visit o.left, a} >> #{visit o.right, o.left}"
      end

      def visit_Arel_Nodes_ContainsEquals o, a = nil
        "#{visit o.left, a} >>= #{visit o.right, o.left}"
      end

      def visit_Arel_Nodes_Overlap o, a = nil
        "#{visit o.left, a} && #{visit o.right, o.left}"
      end

      def visit_IPAddr value, a = nil
        "'#{value.to_s}/#{value.instance_variable_get(:@mask_addr).to_s(2).count('1')}'"
      end
    end
  end
end
