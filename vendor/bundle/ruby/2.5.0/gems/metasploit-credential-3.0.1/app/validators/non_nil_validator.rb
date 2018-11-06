# Validates that an attribute's value is not `nil`, but does allow blank, so is an alternative to
# `validate :attribute, presence: true` when empty should be allowed, but not `nil`.
#
# @example Validation declaration
#   validates :attribute,
#             non_nil: true
class NonNilValidator < ActiveModel::EachValidator
  # Validates `value` is not `nil`.  If `value` is `nil`, then the `:nil` error message is added to `attribute` on
  # `model`.
  #
  # @param model [#errors] the ActiveModel or ActiveRecord being validated
  # @param attribute [Symbol] the name of the attribute being validated whose value is `value`.
  # @param value [Object, nil] the value of `attribute`.
  # @return [void]
  def validate_each(model, attribute, value)
    if value.nil?
      model.errors.add(attribute, :nil)
    end
  end
end