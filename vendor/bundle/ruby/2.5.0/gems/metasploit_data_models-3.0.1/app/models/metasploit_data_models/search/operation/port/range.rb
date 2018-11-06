# Search operation on an attribute that holds a port number and is being search with a range of port numbers.  The
# range is specified as `<min>-<max>` with `<min>` being less than `<max>` and both being within
# {MetasploitDataModels::Search::Operation::Port::Range the valid port range}.
class MetasploitDataModels::Search::Operation::Port::Range < MetasploitDataModels::Search::Operation::Range
  #
  # Validations
  #

  validate :ports

  #
  # Instance Methods
  #

  # Sets `#value` to a range of ports.
  #
  # @param formatted_value [#to_s] '\d+-\d+'
  def value=(formatted_value)
    super(formatted_value)

    # could not be a `Range` if super conversion failed
    # setters return the argument, not the return value from the method, so access `#value` directly
    if value.is_a? Range
      begin
        # use Integer() instead of String#to_i as String#to_i will ignore trailing letters (i.e. '1two' -> 1) and turn all
        # string without an integer in it to 0.
        integer_begin = Integer(value.begin.to_s)
        integer_end = Integer(value.end.to_s)
      rescue ArgumentError
        # setter returned is ignored in MRI, but do it anyway for other implementation
        @value
      else
        @value = Range.new(integer_begin, integer_end)
      end
    else
      # setter returned is ignored in MRI, but do it anyway for other implementation
      # return unconvertible value from `super`
      @value
    end
  end

  private

  # @note `#value` should be check to be a `Range` before calling {#port}.
  #
  # Validate that either `Range#begin` or `Range#end` is a valid port number in `#value`
  #
  # @param extreme [:begin, :end] Which extreme of the `Range` in `value` to validate.
  # @return [void]
  def port(extreme)
    extreme_value = value.send(extreme)

    if extreme_value.is_a? Integer
      unless MetasploitDataModels::Search::Operation::Port::Number::RANGE.cover?(extreme_value)
        errors.add(
            :value,
            :port_range_extreme_inclusion,
            extreme: extreme,
            extreme_value: extreme_value,
            maximum: MetasploitDataModels::Search::Operation::Port::Number::MAXIMUM,
            minimum: MetasploitDataModels::Search::Operation::Port::Number::MINIMUM
        )
      end
    else
      errors.add(:value, :port_range_extreme_not_an_integer, extreme: extreme, extreme_value: extreme_value)
    end
  end

  # Validates that the `Range#begin` and `Range#end` of `#value` are valid port numbers.
  #
  # @return [void]
  def ports
    if value.is_a? Range
      [:begin, :end].each do |extreme|
        port(extreme)
      end
    end
  end
end