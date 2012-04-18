require 'test_helper'

class StrainerTest < Test::Unit::TestCase
  include Liquid

  def test_strainer
    strainer = Strainer.create(nil)
    assert_equal false, strainer.respond_to?('__test__')
    assert_equal false, strainer.respond_to?('test')
    assert_equal false, strainer.respond_to?('instance_eval')
    assert_equal false, strainer.respond_to?('__send__')
    assert_equal true, strainer.respond_to?('size') # from the standard lib
  end

  def test_should_respond_to_two_parameters
    strainer = Strainer.create(nil)
    assert_equal true, strainer.respond_to?('size', false)
  end

  # Asserts that Object#respond_to_missing? is not being undefined in Ruby versions where it has been implemented
  # Currently this method is only present in Ruby v1.9.2, or higher
  def test_object_respond_to_missing
    assert_equal Object.respond_to?(:respond_to_missing?), Strainer.create(nil).respond_to?(:respond_to_missing?)
  end
end # StrainerTest
