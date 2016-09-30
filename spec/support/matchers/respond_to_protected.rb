RSpec::Matchers.define :respond_to_protected do |method_name|
  protected_and_private = true

  match do |receiver|
    receiver.respond_to?(method_name, protected_and_private)
  end
end