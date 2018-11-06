# Concerns type casting of a raw value to an `Integer`.
module Metasploit::Model::Search::Operation::Value::Integer
  #
  # Attributes
  #

  # @!attribute [r] value_before_type_cast
  #   The formatted version of {#value} before it was type cast when calling {#value=}.
  #
  #   @return [Object]
  attr_reader :value_before_type_cast

  #
  # Methods
  #

  # Sets {Metasploit::Model::Search::Operation::Base#value} by type casting String to Integer.
  #
  # @param formatted_value [#to_s]
  # @return [Integer] if `formatted_value` contains only an Integer#to_s
  # @return [#to_s] `formatted_value` if it does not contain an Integer#to_s
  def value=(formatted_value)
    @value_before_type_cast = formatted_value

    begin
      # use Integer() instead of String#to_i as String#to_i will ignore trailing letters (i.e. '1two' -> 1) and turn all
      # string without an integer in it to 0.
      @value = Integer(formatted_value.to_s)
    rescue ArgumentError
      @value = formatted_value
    end
  end
end