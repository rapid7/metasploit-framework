require File.dirname(__FILE__) + "/helper"

class GlobalObjectTest < Test::Unit::TestCase
  include RKelly::JS

  def setup
    @object = GlobalObject.new
  end

  def test_initialize
    assert_equal :undefined, @object['prototype'].value
    assert_equal 'GlobalObject', @object['class'].value
  end

  def test_braces
    @object['foo'] = 'blah'
    assert @object.has_property?('foo')
    assert @object['foo']
    assert_equal('blah', @object['foo'].value)
  end

  def test_undefined_brace
    #assert_equal :undefined, @object['foo'].value
  end

  def test_delete
    assert !@object.has_property?('foo')
    @object['foo'] = 'blah'
    assert @object.has_property?('foo')
    assert @object.delete('foo')
    assert !@object.has_property?('foo')
  end

  def test_can_put
    @object['foo'] = 'blah'
    @object['foo'].attributes << :read_only
    assert @object['foo'].read_only?
  end

  def test_prototype
    proto = GlobalObject.new
    proto['foo'] = 'bar'
    assert proto.has_property?('foo')

    assert !@object.has_property?('foo')
    @object['prototype'] = proto
    assert @object.has_property?('foo')
  end
end
