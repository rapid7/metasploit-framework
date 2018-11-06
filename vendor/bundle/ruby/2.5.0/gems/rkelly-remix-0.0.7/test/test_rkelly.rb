require File.dirname(__FILE__) + "/helper"

class RKellyTest < Test::Unit::TestCase
  def test_array_access
    assert_sexp(
      [
        [:var,
          [[:var_decl, :a,
            [:assign, [:bracket_access, [:resolve, "foo"], [:lit, 10]]],
          ]]
        ]
      ],
      RKelly.parse('var a = foo[10];'))
  end

  def assert_sexp(expected, node)
    assert_equal(expected, node.to_sexp)
  end
end
