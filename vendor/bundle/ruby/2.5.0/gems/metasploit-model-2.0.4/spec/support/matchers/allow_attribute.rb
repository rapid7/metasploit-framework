RSpec::Matchers.define :allow_attribute do |attribute|
  description do
    "allow zero or more items for #{attribute}"
  end

  failure_message do |module_instance|
    "expected that #{module_instance} with #{module_instance.module_type} #module_type would allow #{attribute} zero or more items"
  end

  failure_message_when_negated do |module_instance|
    "expected that #{module_instance} with #{module_instance.module_type} would not allow #{attribute} zero or more items"
  end

  match do |module_instance|
    module_instance.allows?(attribute)
  end
end