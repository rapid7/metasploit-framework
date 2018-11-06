require File.dirname(__FILE__) + "/helper"

class AutomaticSemicolonInsertionTest < Test::Unit::TestCase
  def setup
    @parser = RKelly::Parser.new
  end

  def test_basic_statement
    assert_sexp(
      [
        [:return,
          [:lit, 12]]
      ],
      @parser.parse('return 12'))
  end

  def test_multiline_expression
    assert_sexp(
      [
        [:expression,
          [:add,
            [:lit, 1],
            [:lit, 1]
          ]
        ]
      ],
      @parser.parse("1 +\n1"))
  end

  def test_multiple_statements
    assert_sexp(
      [
        [:var,
          [
            [:var_decl, :foo, nil]
          ]
        ],
        [:var,
          [
            [:var_decl, :bar, nil]
          ]
        ]
      ],
      @parser.parse("var foo\nvar bar"))
  end

  def test_bracketed_statement
    assert_sexp(
      [
        [:block,
          [
            [:var,
              [
                [:var_decl, :foo, nil]
              ]
            ]
          ]
        ]
      ],
      @parser.parse("{var foo}"))
  end

  def test_insertion_before_plus_plus
    assert_sexp(
      [
        [:expression,
          [:op_equal,
            [:resolve, "a"],
            [:resolve, "b"]
          ]
        ],
        [:expression,
          [:prefix, [:resolve, "c"], "++"]
        ]
      ],
      @parser.parse("a = b\n++c"))
  end

  def test_insertion_before_minus_minus
    assert_sexp(
      [
        [:expression,
          [:op_equal,
            [:resolve, "a"],
            [:resolve, "b"]
          ]
        ],
        [:expression,
          [:prefix, [:resolve, "c"], "--"]
        ]
      ],
      @parser.parse("a = b\n--c"))
  end

  def test_insertion_after_continue
    assert_sexp(
      [
        [:continue],
        [:expression, [:resolve, "foo"]]
      ],
      @parser.parse("continue\nfoo"))
  end

  def test_insertion_after_break
    assert_sexp(
      [
        [:break],
        [:expression, [:resolve, "foo"]]
      ],
      @parser.parse("break\nfoo"))
  end

  def test_insertion_after_return
    assert_sexp(
      [
        [:return],
        [:expression, [:resolve, "foo"]]
      ],
      @parser.parse("return\nfoo"))
  end

  def test_insertion_after_throw
    assert_nil @parser.parse("throw\nfoo")
  end

  def test_no_empty_statement_insertion
    assert_nil @parser.parse("if (a > b)\nelse c = d")
  end

  def test_no_for_insertion
    assert_nil @parser.parse("for (a;b\n){}")
  end

  def assert_sexp(expected, node)
    assert_equal(expected, node.to_sexp)
  end
end
