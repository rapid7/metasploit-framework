# Concerns type casting of a raw value to a `String`.
module Metasploit::Model::Search::Operation::Value::String
  #
  # Methods
  #

  # Sets {Metasploit::Model::Search::Operation::Base#value} by type casting to a String.
  #
  # @param formatted_value [#to_s]
  # @return [String]
  def value=(formatted_value)
    @value = formatted_value.to_s
  end
end