# Use search operators registered on an associated class using
# {Metasploit::Model::Search::Attribute::ClassMethods#search_attribute},
# {Metasploit::Model::Search::With::ClassMethods#search_with}.
#
# Searchable associations are declared explicitly so that associations cycles can be avoided and the search
# interface can be tuned for clarity and complexity.
#
# # Testing
#
# {ClassMethods#search_association} calls can be tested with the 'search_association' shared example.  First,
# ensure the shared examples from `metasploit-model` are required in your `spec_helper.rb`:
#
#     # spec/spec_helper.rb
#     support_glob = Metasploit::Model::Engine.root.join('spec', 'support', '**', '*.rb')
#
#     Dir.glob(support_glob) do |path|
#       require path
#     end
#
# In the spec for the `Class` that called `search_association`, use the 'search_association' shared example:
#
#     # spec/app/models/my_class_spec.rb
#     require 'spec_helper'
#
#     describe MyClass do
#       context 'search' do
#         context 'associations' do
#           it_should_be_like 'search_association', :association_name
#         end
#       end
#     end
#
# @example Search near and far associations
#   class Root
#     include Metasploit::Model::Association
#     include Metasploit::Model::Search
#
#     #
#     # Associations
#     #
#
#     association :children,
#                 class_name: 'Child'
#
#     #
#     # Search
#     #
#
#     search_association children: :grandchildren
#   end
#
#   class Child
#     include Metasploit::Model::Association
#     include Metasploit::Model::Search
#
#     #
#     # Associations
#     #
#
#     association :grandchildren,
#                 class_name: 'Grandchild'
#
#     #
#     # Search
#     #
#
#     search_attribute :name,
#                      type: :string
#   end
#
#   class Grandchild
#     include Metasploit::Model::Search
#
#     search_attribute :age,
#                      type: :integer
#   end
#
#   Root.search_operator_by_name.each_value
#   # :'children.name'
#   # :'children.grandchildren.age'
#
#   Child.search_operator_by_name.each_value
#   # :name
#   # @note ``:'grandchildren.age'`` is not in `Child`'s operators because it didn't declare
#   #   `search_association :grandchildren`, only `Root` did.
#
#   Grandchild.search_operator_name
#   # :age
#
module Metasploit::Model::Search::Association
  extend ActiveSupport::Concern

  # Adds {#search_association} DSL to make {Metasploit::Model::Search::Operator::Association association search
  # operators}.
  module ClassMethods
    # @note Use {#search_associations} to declare multiple associations or a tree of far associations as
    #   searchable.
    #
    # Registers association for search.
    #
    # @example a single searchable association
    #   search_association :children
    #
    # @param association [#to_sym] name of association to search.
    # @return [void]
    # @see #search_associations
    def search_association(association)
      search_association_tree[association.to_sym] ||= nil
    end

    # Registers a tree of near and far associations for search.  When a tree is used, all intermediate association
    # on the paths are used, so `search_association children: :grandchildren` makes both `children.granchildren`
    # *and* `children` as search operator prefixes.
    #
    # @example a single search association
    #   search_associations :children
    #
    # @example multiple near associations
    #   search_associations :first,
    #                       :second
    #
    # @example far association
    #   search_associations near: :far
    #
    # @example multiple far associations
    #   search_associations near: [
    #                         :first_far,
    #                         :second_far
    #                       ]
    #
    # @example mix of near and far associations
    #   # Keep associations in order by near association names by mixing Symbols and Hash{Symbol => Object}
    #   search_associations :apple,
    #                       {
    #                         banana: :peel
    #                       },
    #                       :cucumber
    #
    #
    # @param associations [Array<Array, Hash, Symbol>, Hash, Symbol]
    # @return [void]
    # @see search_association
    def search_associations(*associations)
      expanded_associations = Metasploit::Model::Association::Tree.expand(associations)

      @search_association_tree = Metasploit::Model::Association::Tree.merge(
          search_association_tree,
          expanded_associations
      )
    end

    # The association operators for the searchable associations declared with {#search_association} and
    # {#search_associations}.
    #
    # @return (see Metasploit::Model::Association::Tree.operators)
    def search_association_operators
      @search_association_operators ||= Metasploit::Model::Association::Tree.operators(
          search_association_tree,
          class: self
      )
    end

    # Tree of associations that are searchable.
    #
    # @return [Hash{Symbol => Hash,nil}]
    def search_association_tree
      @search_association_tree ||= {}
    end
  end
end
