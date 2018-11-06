# Operator used when the formatted operator name does not match a class's operators.
class Metasploit::Model::Search::Operator::Null < Metasploit::Model::Search::Operator::Single
  #
  # Attributes
  #

  # @!attribute [rw] name
  #   The name of this operator that was not the name of a search operator for
  #   {Metasploit::Model::Search::Operator::Base#klass}.
  #
  #   @return [Symbol]
  attr_accessor :name

  #
  # Validations
  #

  validate :name_invalid

  # Null operators do not have a type since the attribute is unknown.
  #
  # @return [nil]
  def type
    nil
  end

  protected

  # Null operation Class.
  #
  # @return [Class] {Metasploit::Model::Search::Operation::Null}
  def operation_class
    Metasploit::Model::Search::Operation::Null
  end

  private

  # Always records an error that name is not an operator name
  #
  # @return [void]
  def name_invalid
    errors.add(:name, :unknown)
  end
end