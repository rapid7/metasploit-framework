class FangedValidator < ActiveModel::EachValidator
  def validate_each(record, attribute, value)
    if value && value.defanged?
      record.errors.add(attribute, :defanged)
    end
  end
end