# Search operation with {Metasploit::Model::Search::Operation::Base#operator} with `#type` ':date'.  Validates that
# value is `String` that can parsed with `Date.parse` or already a `Date`.
class Metasploit::Model::Search::Operation::Date < Metasploit::Model::Search::Operation::Base
  #
  # Validations
  #

  validate :date_value

  #
  # Methods
  #

  # Sets {Metasploit::Model::Search::Operation::Base#value} by type casting String to actual Date.
  #
  # @param formatted_value [#to_s]
  # @return [Date] if `formatted_value.to_s` is parseable with `Date.parse`.
  # @return [#to_s] `formatted_value` if `formatted_value` is not parseable with `Date.parse`.
  def value=(formatted_value)
    begin
      @value = Date.parse(formatted_value.to_s)
    rescue ArgumentError
      @value = formatted_value
    end
  end

  private

  # Validates that {#value} is a `Date`.
  #
  # @return [void]
  def date_value
    unless value.is_a? Date
      errors.add(:value, :unparseable_date)
    end
  end
end