module ActiveRecord
  module QueryMethods
    class WhereChain
      def overlap(opts, *rest)
        substitute_comparisons(opts, rest, Arel::Nodes::Overlap, 'overlap')
      end

      def contained_within(opts, *rest)
        substitute_comparisons(opts, rest, Arel::Nodes::ContainedWithin, 'contained_within')
      end

      def contained_within_or_equals(opts, *rest)
        substitute_comparisons(opts, rest, Arel::Nodes::ContainedWithinEquals, 'contained_within_or_equals')
      end

      def contains(opts, *rest)
        build_where_chain(opts, rest) do |rel|
          case rel
          when Arel::Nodes::In, Arel::Nodes::Equality
            column = left_column(rel) || column_from_association(rel)
            equality_for_hstore(rel) if column.type == :hstore

            if column.type == :hstore
              Arel::Nodes::ContainsHStore.new(rel.left, rel.right)
            elsif column.respond_to?(:array) && column.array
              Arel::Nodes::ContainsArray.new(rel.left, rel.right)
            else
              Arel::Nodes::ContainsINet.new(rel.left, rel.right)
            end
          else
            raise ArgumentError, "Invalid argument for .where.overlap(), got #{rel.class}"
          end
        end
      end

      def contained_in_array(opts, *rest)
        build_where_chain(opts, rest) do |rel|
          case rel
          when Arel::Nodes::In, Arel::Nodes::Equality
            column = left_column(rel) || column_from_association(rel)
            equality_for_hstore(rel) if column.type == :hstore

            if column.type == :hstore
              Arel::Nodes::ContainedInHStore.new(rel.left, rel.right)
            elsif column.respond_to?(:array) && column.array
              Arel::Nodes::ContainedInArray.new(rel.left, rel.right)
            else
              Arel::Nodes::ContainsINet.new(rel.left, rel.right)
            end
          else
            raise ArgumentError, "Invalid argument for .where.overlap(), got #{rel.class}"
          end
        end
      end

      def contains_or_equals(opts, *rest)
        substitute_comparisons(opts, rest, Arel::Nodes::ContainsEquals, 'contains_or_equals')
      end

      def any(opts, *rest)
        equality_to_function('ANY', opts, rest)
      end

      def all(opts, *rest)
        equality_to_function('ALL', opts, rest)
      end

      private

      def find_column(col, rel)
        col.name == rel.left.name.to_s || col.name == rel.left.relation.name.to_s
      end

      def left_column(rel)
        rel.left.relation.engine.columns.find { |col| find_column(col, rel) }
      end

      def column_from_association(rel)
        if assoc = assoc_from_related_table(rel)
          column = assoc.klass.columns.find { |col| find_column(col, rel) }
        end
      end

      def equality_for_hstore(rel)
        new_right_name = rel.left.name.to_s
        if rel.right.respond_to?(:val)
          return if rel.right.val.is_a?(Hash)
          rel.right = Arel::Nodes.build_quoted({new_right_name => rel.right.val},
                                               rel.left)
        else
          return if rel.right.is_a?(Hash)
          rel.right = {new_right_name => rel.right }
        end

        rel.left.name = rel.left.relation.name.to_sym
        rel.left.relation.name = rel.left.relation.engine.table_name
      end

      def assoc_from_related_table(rel)
        engine = rel.left.relation.engine
        engine.reflect_on_association(rel.left.relation.name.to_sym) ||
          engine.reflect_on_association(rel.left.relation.name.singularize.to_sym)
      end

      def build_where_chain(opts, rest, &block)
        where_value = @scope.send(:build_where, opts, rest).map(&block)
        @scope.references!(PredicateBuilder.references(opts)) if Hash === opts
        @scope.where_values += where_value
        @scope
      end

      def substitute_comparisons(opts, rest, arel_node_class, method)
        build_where_chain(opts, rest) do |rel|
          case rel
          when Arel::Nodes::In, Arel::Nodes::Equality
            arel_node_class.new(rel.left, rel.right)
          else
            raise ArgumentError, "Invalid argument for .where.#{method}(), got #{rel.class}"
          end
        end
      end

      def equality_to_function(function_name, opts, rest)
        build_where_chain(opts, rest) do |rel|
          case rel
          when Arel::Nodes::Equality
            Arel::Nodes::Equality.new(rel.right, Arel::Nodes::NamedFunction.new(function_name, [rel.left]))
          else
            raise ArgumentError, "Invalid argument for .where.#{function_name.downcase}(), got #{rel.class}"
          end
        end
      end
    end

    # WithChain objects act as placeholder for queries in which #with does not have any parameter.
    # In this case, #with must be chained with #recursive to return a new relation.
    class WithChain
      def initialize(scope)
        @scope = scope
      end

      # Returns a new relation expressing WITH RECURSIVE
      def recursive(*args)
        @scope.with_values += args
        @scope.recursive_value = true
        @scope
      end
    end

    [:with].each do |name|
      class_eval <<-CODE, __FILE__, __LINE__ + 1
       def #{name}_values                   # def select_values
         @values[:#{name}] || []            #   @values[:select] || []
       end                                  # end
                                            #
       def #{name}_values=(values)          # def select_values=(values)
         raise ImmutableRelation if @loaded #   raise ImmutableRelation if @loaded
         @values[:#{name}] = values         #   @values[:select] = values
       end                                  # end
      CODE
    end

    [:rank, :recursive].each do |name|
      class_eval <<-CODE, __FILE__, __LINE__ + 1
        def #{name}_value=(value)            # def readonly_value=(value)
          raise ImmutableRelation if @loaded #   raise ImmutableRelation if @loaded
          @values[:#{name}] = value          #   @values[:readonly] = value
        end                                  # end

        def #{name}_value                    # def readonly_value
          @values[:#{name}]                  #   @values[:readonly]
        end                                  # end
      CODE
    end

    def with(opts = :chain, *rest)
      if opts == :chain
        WithChain.new(spawn)
      elsif opts.blank?
        self
      else
        spawn.with!(opts, *rest)
      end
    end

    def with!(opts = :chain, *rest) # :nodoc:
      if opts == :chain
        WithChain.new(self)
      else
        self.with_values += [opts] + rest
        self
      end
    end

    def ranked(options = :order)
      spawn.ranked! options
    end

    def ranked!(value)
      self.rank_value = value
      self
    end

    def build_arel_with_extensions
      arel = build_arel_without_extensions

      build_with(arel)

      build_rank(arel, rank_value) if rank_value

      arel
    end

    def build_with(arel)
      with_statements = with_values.flat_map do |with_value|
        case with_value
        when String
          with_value
        when Hash
          with_value.map  do |name, expression|
            case expression
            when String
              select = Arel::Nodes::SqlLiteral.new "(#{expression})"
            when ActiveRecord::Relation, Arel::SelectManager
              select = Arel::Nodes::SqlLiteral.new "(#{expression.to_sql})"
            end
            Arel::Nodes::As.new Arel::Nodes::SqlLiteral.new("\"#{name.to_s}\""), select
          end
        when Arel::Nodes::As
          with_value
        end
      end
      unless with_statements.empty?
        if recursive_value
          arel.with :recursive, with_statements
        else
          arel.with with_statements
        end
      end
    end

    def build_rank(arel, rank_window_options)
      unless arel.projections.count == 1 && Arel::Nodes::Count === arel.projections.first
        rank_window = case rank_window_options
                      when :order
                        arel.orders
                      when Symbol
                        table[rank_window_options].asc
                      when Hash
                        rank_window_options.map { |field, dir| table[field].send(dir) }
                      else
                        Arel::Nodes::SqlLiteral.new "(#{rank_window_options})"
                      end

        unless rank_window.blank?
          rank_node = Arel::Nodes::SqlLiteral.new 'rank()'
          window = Arel::Nodes::Window.new
          if String === rank_window
            window = window.frame rank_window
          else
            window = window.order(rank_window)
          end
          over_node = Arel::Nodes::Over.new rank_node, window

          arel.project(over_node)
        end
      end
    end

    alias_method_chain :build_arel, :extensions
  end
end
