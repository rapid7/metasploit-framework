require File.dirname(__FILE__) + "/helper"

class CommentsTest < NodeTestCase
  def test_some_comments
    parser = RKelly::Parser.new
    ast = parser.parse(<<-eojs)
      /**
       * This is an awesome test comment.
       */
      function aaron() { // This is a side comment
        var x = 10;
        return 1 + 1; // America!
      }
    eojs

    assert ast
    assert_equal(3, ast.comments.length)
    assert_match('awesome', ast.comments[0].value)
    assert_match('side', ast.comments[1].value)
    assert_match('America', ast.comments[2].value)
  end

  def test_only_comments
    parser = RKelly::Parser.new
    ast = parser.parse(<<-eojs)
      /**
       * The first comment
       */
      /**
       * This is an awesome test comment.
       */
    eojs

    assert ast
    assert_equal(2, ast.comments.length)
  end

  def test_empty_source_results_in_zero_comments
    parser = RKelly::Parser.new
    ast = parser.parse("")

    assert ast
    assert_equal(0, ast.comments.length)
  end
end
