# An operation with a {Metasploit::Model::Search::Operator::Association} for
# {Metasploit::Model::Search::Operation::Base#operator} that wraps a {#source_operation} produced by the
# {Metasploit::Model::Search::Operator::Association#source_operator}.  This allows an arbitrary number of associations
# to be changed together until a non-association operation is found that actually validates the value.
class Metasploit::Model::Search::Operation::Association < Metasploit::Model::Search::Operation::Base
  #
  # Attributes
  #

  # @!attribute source_operation
  #   The operation from the {Metasploit::Model::Search::Operator::Association#source_operator}.
  #
  #   @return [Metasploit::Model::Search::Operation::Base]
  attr_accessor :source_operation

  #
  #
  # Validations
  #
  #

  #
  # Validation Methods
  #

  validate :source_operation_valid

  #
  # Attribute Validations
  #

  validates :source_operation,
            presence: true

  #
  # Instance Methods
  #

  # Explicitly remove value attribute so code that depends on the old behavior will break so downstream developers know
  # to update their code to use source_operation.
  undef_method :value
  undef_method :value=

  private

  # Validates that {#source_operation} is valid.
  #
  # @return [void]
  def source_operation_valid
    # presence validation handles errors when nil
    if source_operation
      unless source_operation.valid?
        errors.add(:source_operation, :invalid)
      end
    end
  end
end