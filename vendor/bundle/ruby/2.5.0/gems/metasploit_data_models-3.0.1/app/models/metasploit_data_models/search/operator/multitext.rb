require 'shellwords'

# Searches multiple text fields by breaking up the formatted value into words and doing text search for each word across
# each operator named in {#operator_names}.
class MetasploitDataModels::Search::Operator::Multitext < Metasploit::Model::Search::Operator::Group::Intersection
  #
  # Attributes
  #

  # @!attribute name
  #   The name of this operator.
  #
  #   @return [Symbol]
  attr_accessor :name

  # @!attribute operator_names
  #   The name of the operators to search across.
  #
  #   @return [Array<Symbol>]
  attr_writer :operator_names

  #
  # Validations
  #

  validates :operator_names,
            length: {
                minimum: 2
            }
  validates :name,
            presence: true

  #
  # Instance Methods
  #

  # Breaks `formatted_value` into words using `Shellwords.split`.  Each word is then searched across all {#operators},
  # where any operator can match for that word.  The search for multiple multiple is intersected, so that additional
  # words can refine the search.
  #
  # @param formatted_value [#to_s]
  # @return [Array<Metasploit::Model::Search::Operation::Group::Union>] Unions to be intersected.
  def children(formatted_value)
    words = Shellwords.split formatted_value.to_s

    words.map { |word|
      child_operators = operators.map { |operator|
        operator.operate_on(word)
      }

      Metasploit::Model::Search::Operation::Group::Union.new(
          children: child_operators,
          operator: self
      )
    }
  end

  # The name of the operators to search for each word.
  #
  # @return [Array<Symbol>] Default to `[]`
  def operator_names
    @operator_names ||= []
  end

  # Operators with {#operator_names}.
  #
  # @return [Array<Metasploit::Model::Search::Operator::Base>]
  def operators
    @operators ||= operator_names.map { |operator_name|
      operator(operator_name)
    }
  end
end