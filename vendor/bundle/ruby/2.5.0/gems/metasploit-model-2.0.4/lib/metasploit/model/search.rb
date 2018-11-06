# DSL to define associations and attributes that can be searched.  Making an association searchable, will expose
# the attributes that association's class defined as searchable.
#
# # Operators
#
# Search operators define how to search against a given `Class`.
#
# ## Attributes
#
# Boolean, `Date`, `Integer`, and `String` attributes can be searched with
# {Metasploit::Model::Search::Attribute::ClassMethods#search_attribute search_attribute}.  `Integer` and `String`
# attributes can be further restricted to a defined `Set` of values.
#
#     class Part
#       include Metasploit::Model::Search
#
#       search_attribute :part,
#                        :integer
#     end
#
# The above defines the `:part` operator on `Part`.
#
# ## Custom search operators
#
# If a search operator does not directly correspond to an attribute or a the attribute needs custom validation, then
# a custom {Metasploit::Model::Search::Operator operator class} can be setup as the search operator
#
#     class Search::Operator::UUID
#       def name
#         :uuid
#       end
#     end
#
#     class Part
#       include Metasploit::Model::Search
#
#       search_with Search::Operator::UUID
#     end
#
# The above defines the `:uuid` operator on `Part`.
#
# ## Associations
#
# Search operators registered with
# {Metasploit::Model::Search::Attribute::ClassMethods#search_attribute search_attribute} or
# {Metasploit::Model::Search::With::ClassMethods#search_with search_with} on an associated `Class` can be searched
# with {Metasploit::Model::Search::Association::ClassMethods#search_association}:
#
#     class Widget
#       include Metasploit::Model::Search
#
#       # declare parts association
#
#       search_association :parts
#     end
#
# The above will define the `:'parts.number'` and `:'parts.uuid'` operator on `Widget`.
#
# # Queries
#
# {include:Metasploit::Model::Search::Query}
module Metasploit::Model::Search
  extend ActiveSupport::Autoload
  extend ActiveSupport::Concern

  autoload :Association
  autoload :Attribute
  autoload :Group
  autoload :Operation
  autoload :Operator
  autoload :Query
  autoload :Search
  autoload :With

  include Metasploit::Model::Search::Association
  include Metasploit::Model::Search::Attribute
  include Metasploit::Model::Search::With

  # Allows operators registered with {Metasploit::Model::Search::Association::ClassMethods#search_association} and
  # {Metasploit::Model::Search::Attribute::ClassMethods#search_attribute} to be looked up by name.
  module ClassMethods
    # Collects all search attributes from search associations and all attributes from this class to show the valid
    # search operators to search.
    #
    # @return [Hash{Symbol => Metasploit::Model::Search::Operator}] Maps
    #   {Metasploit::Model::Search::Operator::Base#name} to {Metasploit::Model::Search::Operator::Base#name}.
    def search_operator_by_name
      unless instance_variable_defined? :@search_operator_by_name
        @search_operator_by_name = {}

        search_with_operator_by_name.each_value do |operator|
          @search_operator_by_name[operator.name] = operator
        end

        search_association_operators.each do |operator|
          @search_operator_by_name[operator.name] = operator
        end
      end

      @search_operator_by_name
    end
  end
end
