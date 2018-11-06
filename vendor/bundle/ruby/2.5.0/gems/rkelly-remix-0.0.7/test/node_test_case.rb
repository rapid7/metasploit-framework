class NodeTestCase < Test::Unit::TestCase
  include RKelly::Nodes

  if method_defined? :default_test
    undef :default_test
  end

  def assert_sexp(expected, actual)
    assert_equal(expected, actual.to_sexp)
  end
end
