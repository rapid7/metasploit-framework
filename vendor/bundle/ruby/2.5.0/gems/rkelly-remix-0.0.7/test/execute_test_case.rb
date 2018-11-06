class ExecuteTestCase < Test::Unit::TestCase
  include RKelly::Nodes

  if method_defined? :default_test
    undef :default_test
  end

  def assert_execute(expected, code)
    scope_chain = @runtime.execute(code)
    expected.each do |name, value|
      assert scope_chain.has_property?(name)
      assert_equal value, scope_chain[name].value
    end
  end
end

