RSpec::Matchers.define :validate_non_nilness_of do |attribute|
  define_method(:message) do
    I18n.translate!(:'errors.messages.nil')
  end

  define_method(:allow_blank) do |instance|
    instance.send("#{attribute}=", '')
    instance.valid?
    instance.errors[attribute].empty?
  end

  define_method(:disallow_nil) do |instance|
    instance.send("#{attribute}=", nil)
    instance.valid?
    !instance.errors[attribute].empty?
  end

  match do |instance|
    allow_blank(instance) && disallow_nil(instance)
  end
end