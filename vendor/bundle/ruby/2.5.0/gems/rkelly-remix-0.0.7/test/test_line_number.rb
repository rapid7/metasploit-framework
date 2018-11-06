require File.dirname(__FILE__) + "/helper"

class LineNumberTest < NodeTestCase
  def test_line_numbers
    parser = RKelly::Parser.new
    ast = parser.parse(<<-eojs)
      /**
       * This is an awesome test comment.
       */
      function aaron() {
        var x = 10;
        return 1 + 1;
      }
    eojs
    func = ast.pointcut(FunctionDeclNode).matches.first
    assert func
    assert_equal(4, func.line)

    return_node = ast.pointcut(ReturnNode).matches.first
    assert return_node
    assert_equal(6, return_node.line)
  end

  def test_ranges
    parser = RKelly::Parser.new
    ast = parser.parse(<<-eojs)
      /**
       * This is an awesome test comment.
       */
      function aaron() {
        var x = 10;
        return 1 + 1;
      }
    eojs
    func = ast.pointcut(FunctionDeclNode).matches.first
    assert func
    assert_equal("<{line:4 char:7 (68)}...{line:7 char:7 (135)}>", func.range.to_s)

    return_node = ast.pointcut(ReturnNode).matches.first
    assert return_node
    assert_equal("<{line:6 char:9 (115)}...{line:6 char:21 (127)}>", return_node.range.to_s)
  end

  def test_range_of_var_statement_with_semicolon
    parser = RKelly::Parser.new
    ast = parser.parse(<<-eojs)
      var x = {
        foo: 10,
        bar: "blah"
      };
    eojs
    stmt = ast.pointcut(VarStatementNode).matches.first
    assert_equal("<{line:1 char:7 (6)}...{line:4 char:8 (60)}>", stmt.range.to_s)
  end

  def test_range_of_var_statement_without_semicolon
    parser = RKelly::Parser.new
    ast = parser.parse(<<-eojs)
      var x = {
        foo: 10,
        bar: "blah"
      }
    eojs
    stmt = ast.pointcut(VarStatementNode).matches.first
    assert_equal("<{line:1 char:7 (6)}...{line:4 char:7 (59)}>", stmt.range.to_s)
  end

  def test_range_of_empty_function_body
    parser = RKelly::Parser.new
    ast = parser.parse(<<-eojs)
      function f () {
      }
    eojs

    stmt = ast.pointcut(FunctionDeclNode).matches.first
    assert_equal("<{line:1 char:7 (6)}...{line:2 char:7 (28)}>", stmt.range.to_s)

    stmt = ast.pointcut(FunctionBodyNode).matches.first
    assert_equal("<{line:1 char:21 (20)}...{line:2 char:7 (28)}>", stmt.range.to_s)
  end
end
