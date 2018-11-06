# Operation that uses a {Metasploit::Model::Search::Operation::Null null operator}.
class Metasploit::Model::Search::Operation::Null < Metasploit::Model::Search::Operation::Base
  #
  # Validations
  #

  validate :null_operator

  #
  # Methods
  #

  private

  # Validates that {Metasploit::Model::Search::Operation::Base#operator} is a
  # {Metasploit::Model::Search::Operator::Null}, as {Metasploit::Model::Search::Operation::Null} won't validate
  # correctly (and be invalid) if {Metasploit::Model::Search::Operation::Base#operator} is not a
  # {Metasploit::Model::Search::Operator::Null}.
  #
  # @return [void]
  def null_operator
    unless operator.is_a? Metasploit::Model::Search::Operator::Null
      errors.add(:operator, :type, :type => Metasploit::Model::Search::Operator::Null)
    end
  end
end