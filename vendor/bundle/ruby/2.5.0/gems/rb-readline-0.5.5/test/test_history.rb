require "minitest/autorun"
require "readline"

class TestHistory < Minitest::Test

  # RbReadline::HISTORY_WORD_DELIMITERS.inspect
  # => " \t\n;&()|<>"
  # RbReadline::HISTORY_QUOTE_CHARACTERS   = "\"'`"
  # => "\"'`"
  def test_history_arg_extract
    assert_raises(RuntimeError) { RbReadline.history_arg_extract("!", "$", "one two three") }
    assert_raises(RuntimeError) { RbReadline.history_arg_extract("$", "!", "one two three") }

    assert_equal "one", RbReadline.history_arg_extract("$", "$", "one")
    assert_equal "three", RbReadline.history_arg_extract("$", "$", "one two three")
    assert_equal "two\\ three", RbReadline.history_arg_extract("$", "$", "one two\\ three")
    assert_equal "three", RbReadline.history_arg_extract("$", "$", "one two;three")
    assert_equal "two\\;three", RbReadline.history_arg_extract("$", "$", "one two\\;three")

    assert_equal "'two three'", RbReadline.history_arg_extract("$", "$", "one 'two three'")
    assert_equal "`two three`", RbReadline.history_arg_extract("$", "$", "one `two three`")
    assert_equal "three\\'", RbReadline.history_arg_extract("$", "$", "one \\'two three\\'")
    assert_equal "`one`", RbReadline.history_arg_extract("$", "$", "`one`")

    assert_equal "three'", RbReadline.history_arg_extract("$", "$", "one two three'")
    assert_equal "three", RbReadline.history_arg_extract("$", "$", "one two' three")
    assert_equal "'two three '", RbReadline.history_arg_extract("$", "$", "one 'two three '")
  end
end
