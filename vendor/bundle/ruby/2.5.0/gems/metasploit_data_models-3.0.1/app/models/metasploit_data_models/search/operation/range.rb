# Search operation on a `Range`.
class MetasploitDataModels::Search::Operation::Range < Metasploit::Model::Search::Operation::Base
  #
  # CONSTANTS
  #

  # Separates beginning from end of the range.
  SEPARATOR = '-'

  #
  # Validation
  #

  validate :ordered
  validate :range

  #
  # Instance Methods
  #

  # Sets `#value` to a `Range` composed by separating `formatted_value` by `-`.
  #
  # @param formatted_value [#to_s]
  # @return [Range<String>]
  def value=(formatted_value)
    range_arguments = formatted_value.to_s.split(SEPARATOR, 2)

    begin
      @value = Range.new(*range_arguments)
    rescue ArgumentError
      @value = formatted_value
    end

    @value
  end

  private

  # Validates that `#value` is a `Range` with `Range#begin` less than or equal to `Range#begin`
  #
  # @return [void]
  def ordered
    if value.is_a?(Range) && value.begin > value.end
      errors.add(:value, :order, begin: value.begin.inspect, end: value.end.inspect)
    end
  end

  # Validates that `#value` is a `Range`
  #
  # @return [void]
  def range
    unless value.is_a? Range
      errors.add(:value, :range)
    end
  end
end