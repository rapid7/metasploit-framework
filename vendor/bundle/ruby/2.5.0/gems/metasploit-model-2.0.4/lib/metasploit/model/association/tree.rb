# Functions for turning a compact tree of compact as passed to
# {Metasploit::Model::Search::Association::ClassMethods#search_associations} into an expanded
# {Metasploit::Model::Search::Association::ClassMethods#search_association_tree}.
module Metasploit::Model::Association::Tree
  # Expands a `compact` association into an expanded association tree.
  #
  # @param compact [Array, Hash{Symbol => Array,Hash,Symbol}, Symbol] a compact association as passed to
  #   {Metasploit::Model::Search::Association::ClassMethods#search_associations}.
  # @return [Hash{Symbol => Hash,nil}]
  def self.expand(compact)
    case compact
      when Array
        compact.reduce({}) { |hash, association|
          hash.merge(expand(association))
        }
      when Hash
        child_by_parent = compact

        child_by_parent.each_with_object({}) { |(parent, child), hash|
          hash[parent] = expand(child)
        }
      when Symbol
        association = compact

        {association => nil}
    end
  end

  # @note Unlike `Hash#deep_merge`, `second_expanded`'s values aren't favored over `first`'s values.  Instead whichever
  #   side is present is used and if both `first` and `second_expanded` are present, then their `Hash#key`s' values are
  #   recursively merged.
  #
  # Merges two expanded association trees.
  #
  # @param first_expanded [nil, Hash{Symbol => nil,Hash}] An expanded association tree as from {expand}
  # @param second_expanded [nil, Hash{Symbol => nil,Hash}] An expanded association tree as from {expand}
  # @return [nil, Hash{Symbol => nil,Hash}] a new expanded association tree.
  def self.merge(first_expanded, second_expanded)
    if first_expanded.nil? && second_expanded.nil?
      nil
    elsif !first_expanded.nil? && second_expanded.nil?
      first_expanded
    elsif first_expanded.nil? && !second_expanded.nil?
      second_expanded
    else
      first_keys = first_expanded.keys
      key_set = Set.new(first_keys)

      second_keys = second_expanded.keys
      key_set.merge(second_keys)

      key_set.each_with_object({}) do |key, merged|
        first_child = first_expanded[key]
        second_child = second_expanded[key]

        merged[key] = merge(first_child, second_child)
      end
    end
  end

  # Calculates association operators for the `expanded` association tree.
  #
  # @param expanded [Hash{Symbol => Hash,nil}, nil] An expanded association tree.
  # @param options [Hash{Symbol => Class}]
  # @option options [Class, #reflect_on_association] :class The `Class` on which the top-level key associations in
  #   `expanded` are declared.
  # @return [Array<Metasploit::Model::Search::Operator::Association>]
  def self.operators(expanded, options={})
    expanded ||= {}

    options.assert_valid_keys(:class)
    klass = options.fetch(:class)

    expanded.flat_map { |parent_association, child_tree|
      reflection = reflect_on_association_on_class(parent_association, klass)
      association_class = reflection.klass

      association_search_with_operators = association_class.search_with_operator_by_name.each_value

      child_tree_operators = operators(
          child_tree,
          class: reflection.klass
      )

      [association_search_with_operators, child_tree_operators].flat_map { |enumerator|
        enumerator.map { |source_operator|
          Metasploit::Model::Search::Operator::Association.new(
              association: parent_association,
              klass: klass,
              source_operator: source_operator
          )
        }
      }
    }
  end

  private

  # Return the association reflection for `association` on `klass`.
  #
  # @param association [Symbol] name of an association on `klass`.
  # @param klass [#reflect_on_association] `Class` on which `association` is declared.
  # @return [#klass] Association reflection that can give the `#klass` pointed to by the association.
  # @raise [Metasploit::Model::Association::Error] if `association` is not declared on `klass`.
  # @raise [NameError] if `klass` does not respond to `reflect_on_association`.
  def self.reflect_on_association_on_class(association, klass)
    begin
      reflection = klass.reflect_on_association(association)
    rescue NameError
      raise NameError,
            "#{self} does not respond to reflect_on_association.  " \
                      "It can be added to ActiveModels by including Metasploit::Model::Association into the class."
    end

    unless reflection
      raise Metasploit::Model::Association::Error.new(
                model: klass,
                name: association
            )
    end

    reflection
  end
end
