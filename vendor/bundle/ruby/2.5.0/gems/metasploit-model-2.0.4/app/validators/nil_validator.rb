# Validator to ensure an attribute is `nil`.  Intended for use conditionally with `:if` or `:unless` to ensure an
# attribute is `nil` under one condition while a different validation, such as `:presence` or `:inclusion` is used under
# the dual of that condition.
class NilValidator < ActiveModel::EachValidator
  # Validates that `value` is `nil`.
  #
  # @param record [#errors, ActiveRecord::Base] an ActiveModel or ActiveRecord
  # @param attribute [Symbol] name of attribute being validated.
  # @param value [#nil?] value of `attribute` to check with `nil?`
  # @return [void]
  def validate_each(record, attribute, value)
    unless value.nil?
      record.errors[attribute] << 'must be nil'
    end
  end
end