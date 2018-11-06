# Adds a {#match match class method} to the extending class.  The extending class must define `MATCH_REGEXP`.
#
# @example Define `match` class method
#   class MetasploitDataModels::Format
#     extend MetasploitDataModels::Match::Child
#
#     #
#     # CONSTANTS
#     #
#
#     # Regular expression {MetasploitDataModels::Match#match} must match against.
#     MATCH_REGEXP = /\A...\z/
#   end
#
#   # a `MetasploitDataModels::Format` because `'123'` matches `MetasploitDataModels::Format::MATCH_REGEXP`
#   instance = MetapsloitDataModels::Format.match('123')
#   # `nil` because string `'12'` doesn't match `MetasploitDataModels::Format::MATCH_REGEXP`
#   no_instance = MetasploitDataModels::Format.match('12')
#
module MetasploitDataModels::Match::Child
  # Creates a new instance of the extending class if `MATCH_REGEXP`, defined on the extending class, matches
  # `formatted_value`.
  #
  # @param formatted_value [#to_s]
  def match(formatted_value)
    instance = nil

    if match_regexp.match(formatted_value)
      instance = new(value: formatted_value)
    end

    instance
  end

  # Regular expression to match against for {#match}.
  #
  # @return [Regexp] Defaults to {#regexp} pinned with `\A` and `\z`.
  def match_regexp
    @match_regexp ||= /\A#{regexp}\z/
  end

  # Regular expression to match child as part of {MetasploitDataModels::Match::Parent}.
  #
  # @return [Regexp] Default to `REGEXP` from the extending `Class`.
  def regexp
    self::REGEXP
  end
end
