# Base of all search operations that combine an {#operator} with the {#value} it is operating on.  Subclasses allow
# validations specific to the {#operator} {Metasploit::Model::Search::Operator::Single#type type}.
class Metasploit::Model::Search::Operation::Base < Metasploit::Model::Base
  #
  # Attributes
  #

  # @!attribute [rw] operator
  #   The operator operating on {#value}.
  #
  #   @return [Metasploit::Model::Search::Operator::Base]
  attr_accessor :operator

  # @!attribute [rw] value
  #   The value cast to the correct type from the formatted_value from the formatted operation.
  #
  #   @return [String]
  attr_accessor :value

  #
  # Validations
  #

  validates :operator,
            :presence => true
  # validate_associated is defined by ActiveRecord, so have to do it manually here.
  validate :operator_valid

  private

  # Validates that {#operator} is valid
  #
  # @return [void]
  def operator_valid
    if operator and !operator.valid?
      errors.add(:operator, :invalid, :value => operator)
    end
  end
end