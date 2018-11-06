# Search operation with {Metasploit::Model::Search::Operation::Base#operator} with `#type` `:integer`.  Validates that
# value is an integer.
class Metasploit::Model::Search::Operation::Integer < Metasploit::Model::Search::Operation::Base
  include Metasploit::Model::Search::Operation::Value::Integer

  #
  # Validations
  #

  validates :value,
            :numericality => {
                :only_integer => true
            }
end