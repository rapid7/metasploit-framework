# encoding: UTF-8

module ArelHelpers

  module JoinAssociation
    extend ActiveSupport::Concern

    module ClassMethods
      def join_association(*args, &block)
        ArelHelpers::JoinAssociation.join_association(self, *args, &block)
      end
    end

    class << self
      # activerecord uses JoinDependency to automagically generate inner join statements for
      # any type of association (belongs_to, has_many, and has_and_belongs_to_many).
      # For example, for HABTM associations, two join statements are required.
      # This method encapsulates that functionality and yields an intermediate object for chaining.
      # It also allows you to use an outer join instead of the default inner via the join_type arg.
      def join_association(table, association, join_type = Arel::Nodes::InnerJoin, options = {}, &block)
        if version >= '5.2.1'
          join_association_5_2_1(table, association, join_type, options, &block)
        elsif version >= '5.2.0'
          join_association_5_2(table, association, join_type, options, &block)
        elsif version >= '5.0.0'
          join_association_5_0(table, association, join_type, options, &block)
        elsif version >= '4.2.0'
          join_association_4_2(table, association, join_type, options, &block)
        elsif version >= '4.1.0'
          join_association_4_1(table, association, join_type, options, &block)
        else
          join_association_3_1(table, association, join_type, options, &block)
        end
      end

      private

      def version
        ActiveRecord::VERSION::STRING
      end

      def join_association_3_1(table, association, join_type, options = {})
        aliases = options.fetch(:aliases, {})
        associations = association.is_a?(Array) ? association : [association]
        join_dependency = ActiveRecord::Associations::JoinDependency.new(table, associations, [])
        manager = Arel::SelectManager.new(table)

        join_dependency.join_associations.each do |assoc|
          assoc.join_type = join_type
          assoc.join_to(manager)
        end

        manager.join_sources.map do |assoc|
          if found_alias = find_alias(assoc.left.name, aliases)
            assoc.left.table_alias = found_alias.name
          end

          if block_given?
            # yield |assoc_name, join_conditions|
            right = yield assoc.left.name.to_sym, assoc.right
            assoc.class.new(assoc.left, right)
          else
            assoc
          end
        end
      end

      def join_association_4_1(table, association, join_type, options = {})
        aliases = options.fetch(:aliases, {})
        associations = association.is_a?(Array) ? association : [association]
        join_dependency = ActiveRecord::Associations::JoinDependency.new(table, associations, [])

        join_dependency.join_constraints([]).map do |constraint|
          right = if block_given?
            yield constraint.left.name.to_sym, constraint.right
          else
            constraint.right
          end

          if found_alias = find_alias(constraint.left.name, aliases)
            constraint.left.table_alias = found_alias.name
          end

          join_type.new(constraint.left, right)
        end
      end

      # ActiveRecord 4.2 moves bind variables out of the join classes
      # and into the relation. For this reason, a method like
      # join_association isn't able to add to the list of bind variables
      # dynamically. To get around the problem, this method must return
      # a string.
      def join_association_4_2(table, association, join_type, options = {})
        aliases = options.fetch(:aliases, [])
        associations = association.is_a?(Array) ? association : [association]
        join_dependency = ActiveRecord::Associations::JoinDependency.new(table, associations, [])

        constraints = join_dependency.join_constraints([])

        binds = constraints.flat_map do |info|
          info.binds.map { |bv| table.connection.quote(*bv.reverse) }
        end

        joins = constraints.flat_map do |constraint|
          constraint.joins.map do |join|
            right = if block_given?
              yield join.left.name.to_sym, join.right
            else
              join.right
            end

            if found_alias = find_alias(join.left.name, aliases)
              join.left.table_alias = found_alias.name
            end

            join_type.new(join.left, right)
          end
        end

        join_strings = joins.map do |join|
          to_sql(join, table, binds)
        end

        join_strings.join(' ')
      end

      def join_association_5_0(table, association, join_type, options = {})
        aliases = options.fetch(:aliases, [])
        associations = association.is_a?(Array) ? association : [association]
        join_dependency = ActiveRecord::Associations::JoinDependency.new(table, associations, [])

        constraints = join_dependency.join_constraints([], join_type)

        binds = constraints.flat_map do |info|
          prepared_binds = info.binds.map(&:value_for_database)
          prepared_binds.map { |value| table.connection.quote(value) }
        end

        joins = constraints.flat_map do |constraint|
          constraint.joins.map do |join|
            right = if block_given?
              yield join.left.name.to_sym, join.right
            else
              join.right
            end

            if found_alias = find_alias(join.left.name, aliases)
              join.left.table_alias = found_alias.name
            end

            join_type.new(join.left, right)
          end
        end

        join_strings = joins.map do |join|
          to_sql(join, table, binds)
        end

        join_strings.join(' ')
      end

      def join_association_5_2(table, association, join_type, options = {})
        aliases = options.fetch(:aliases, [])
        associations = association.is_a?(Array) ? association : [association]

        alias_tracker = ActiveRecord::Associations::AliasTracker.create(
          table.connection, table.name, {}
        )

        join_dependency = ActiveRecord::Associations::JoinDependency.new(
          table, table.arel_table, associations, alias_tracker
        )

        constraints = join_dependency.join_constraints([], join_type)

        constraints.map do |join|
          right = if block_given?
            yield join.left.name.to_sym, join.right
          else
            join.right
          end

          if found_alias = find_alias(join.left.name, aliases)
            join.left.table_alias = found_alias.name
          end

          join_type.new(join.left, right)
        end
      end

      def join_association_5_2_1(table, association, join_type, options = {})
        aliases = options.fetch(:aliases, [])
        associations = association.is_a?(Array) ? association : [association]

        alias_tracker = ActiveRecord::Associations::AliasTracker.create(
          table.connection, table.name, {}
        )

        join_dependency = ActiveRecord::Associations::JoinDependency.new(
          table, table.arel_table, associations
        )

        constraints = join_dependency.join_constraints([], join_type, alias_tracker)

        constraints.map do |join|
          right = if block_given?
            yield join.left.name.to_sym, join.right
          else
            join.right
          end

          if found_alias = find_alias(join.left.name, aliases)
            join.left.table_alias = found_alias.name
          end

          join_type.new(join.left, right)
        end
      end

      private

      def to_sql(node, table, binds)
        visitor = table.connection.visitor
        collect = visitor.accept(node, Arel::Collectors::Bind.new)
        collect.substitute_binds(binds).join
      end

      def find_alias(name, aliases)
        aliases.find { |a| a.table_name == name }
      end
    end
  end
end
