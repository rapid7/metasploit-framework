RSpec::Matchers.define :validate_nilness_of do |attribute|
  description do
    "require nil for #{attribute}"
  end

  failure_message_method = :failure_message_for_should

  # RSpec compatibility without deprecation warnings
  if respond_to?(:failure_message)
    failure_message_method = :failure_message
  end

  send(failure_message_method) do |instance|
    "Expected errors to include 'must be nil' when #{attribute} is set to an arbitrary string"
  end

  failure_message_when_negated_method = :failure_message_for_should_not

  # RSpec compatibility without deprecation warnings
  if respond_to?(:failure_message_when_negated)
    failure_message_when_negated_method = :failure_message_when_negated
  end

  send(failure_message_when_negated_method) do |instance|
    "Expected errors not to include 'must be nil' when #{attribute} is set"
  end

  match do |instance|
    writer = :"#{attribute}="
    instance.send(writer, nil)
    instance.valid?
    allow_nil = instance.errors[attribute].empty?

    empty = ''
    instance.send(writer, empty)
    instance.valid?
    disallow_empty = instance.errors[attribute].include?('must be nil')

    present = 'present'
    instance.send(writer, present)
    instance.valid?
    disallow_present = instance.errors[attribute].include?('must be nil')

    allow_nil && disallow_empty && disallow_present
  end
end