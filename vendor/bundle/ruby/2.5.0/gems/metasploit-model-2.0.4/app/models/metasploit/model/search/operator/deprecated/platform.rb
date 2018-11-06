# Translates `<name>:<value>` to the union of `platforms.name:<value>` and `targets.name:<value>` in order to support
# the `os` and `platform` operators.
class Metasploit::Model::Search::Operator::Deprecated::Platform < Metasploit::Model::Search::Operator::Group::Union
  #
  # CONSTANTS
  #

  # Formatted operators that should be part of {#children} for this union.
  FORMATTED_OPERATORS = [
      'platforms.fully_qualified_name',
      'targets.name'
  ]

  #
  # Attributes
  #

  # @!attribute [rw] name
  #   Name of this operator
  #
  #   @return [Symbol]
  attr_accessor :name

  #
  # Validations
  #

  validates :name,
            :presence => true

  #
  # Methods
  #

  # Array of `platforms.fully_qualified_name:<formatted_value>` and `targets.name:<formatted_value>` operations.
  #
  # @param formatted_value [String] value parsed from formatted operation.
  # @return [Array<Metasploit::Model::Search::Operation::Base>]
  def children(formatted_value)
    FORMATTED_OPERATORS.collect { |formatted_operator|
      association_operator = operator(formatted_operator)
      association_operator.operate_on(formatted_value)
    }
  end
end