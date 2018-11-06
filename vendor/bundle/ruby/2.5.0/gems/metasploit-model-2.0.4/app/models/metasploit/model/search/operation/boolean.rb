# Search operation with {Metasploit::Model::Search::Operation::Base#operator} with `#type` `:boolean`.  Validates that
# value is a proper boolean (`false` or `true`) or the `String` version of either.
class Metasploit::Model::Search::Operation::Boolean < Metasploit::Model::Search::Operation::Base
  #
  # CONSTANTS
  #

  # Take a String formatted {#value} and returns its unformatted value for validation.
  FORMATTED_VALUE_TO_VALUE = {
      'false' => false,
      'true' => true
  }

  #
  # Validations
  #

  validates :value,
            :inclusion => {
                :in => [
                    false,
                    true
                ],
                :message => :boolean
            }

  # Sets {Metasploit::Model::Search::Operation::Base#value} by type casting String boolean to actual `false` or `true`.
  #
  # @param formatted_value [Object]
  # @return [false] if `formatted_value` is `'false'`.
  # @return [true] if `formatted_value` is `'true'`.
  # @return [Object] `formatted_value` otherwise.
  def value=(formatted_value)
    @value = FORMATTED_VALUE_TO_VALUE.fetch(formatted_value, formatted_value)
  end
end