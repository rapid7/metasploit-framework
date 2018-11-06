# A search operator declared with
# {Metasploit::Model::Search::Association::ClassMethods#search_association search_association}.
class Metasploit::Model::Search::Operator::Association < Metasploit::Model::Search::Operator::Base
  #
  # Attributes
  #

  # @!attribute [rw] association
  #   The association on which {#source_operator} was declared.
  #
  #   @return [Symbol] association on {Metasploit::Model::Search::Operator::Base#klass klass}.
  attr_accessor :association

  # @!attribute [rw] source_operator
  #   The {Metasploit::Model::Search::Operator::Base operator} as declared on the {#association} class.
  #
  #   @return [Metasploit::Model::Search::Operator::Base]
  attr_accessor :source_operator

  #
  # Validations
  #

  validates :association, :presence => true
  validates :source_operator, :presence => true

  #
  # Methods
  #

  delegate :help,
           to: :source_operator

  # The name of this operator.
  #
  # @return [String] <association>.<source_operator.name>
  def name
    @name ||= "#{association}.#{source_operator.name}".to_sym
  end

  # Creates a {Metasploit::Model::Search::Operation::Association} to wrap the original operation returned by
  #   {#source_operator}'s `#operate_on`.
  #
  # @param formatted_value [#to_s] Formatted value to pass to {#source_operator}.
  # @return [Metasploit::Model::Search::Operation::Association] Association operation with the original operation from
  #   {#source_operator} operating on `formatted_value`.
  def operate_on(formatted_value)
    Metasploit::Model::Search::Operation::Association.new(
        operator: self,
        source_operation: source_operator.operate_on(formatted_value)
    )
  end
end