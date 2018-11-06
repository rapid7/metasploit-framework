if defined?(ActiveRecord::Relation)
  RSpec::Matchers::BuiltIn::OperatorMatcher.register(ActiveRecord::Relation, '=~', RSpec::Matchers::BuiltIn::ContainExactly)
end
