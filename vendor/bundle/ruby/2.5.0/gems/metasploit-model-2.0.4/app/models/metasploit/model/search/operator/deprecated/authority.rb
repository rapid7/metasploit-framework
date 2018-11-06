# Operator for the direct, single authority reference search.  Translates `<abbreviation>:<designation>` to
# `authorities.abbreviation:<abbreviation> references.designation:<designation>`.
class Metasploit::Model::Search::Operator::Deprecated::Authority < Metasploit::Model::Search::Operator::Delegation
  #
  # Attributes
  #

  # @!attribute [rw] abbreviation
  #   Value passed to `authorities.abbreviation` operator
  #
  #   @return [String]
  attr_accessor :abbreviation

  #
  # Validations
  #

  validates :abbreviation,
            :presence => true

  #
  # Methods
  #

  alias_method :name, :abbreviation

  # Returns list of operations that search for the authority with {#abbreviation} and `formatted_value` for reference
  # designation.
  #
  # @return [Array<Metasploit::Model::Search::Operation::Base>] authorities.abbreviation:<abbreviation>
  #   references.designation:<formatted_value>
  def operate_on(formatted_value)
    operations = []

    authorities_abbreviation_operator = operator('authorities.abbreviation')
    operations << authorities_abbreviation_operator.operate_on(abbreviation)

    references_designation_operator = operator('references.designation')
    operations << references_designation_operator.operate_on(formatted_value)

    operations
  end
end