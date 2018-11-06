require File.dirname(__FILE__) + "/../helper"

# ECMA-262
# Section 15.1.1.1
class GlobalObject_15_1_1_1_Test < ECMAScriptTestCase
  def setup
    super
    @object = GlobalObject.new
  end

  def test_nan
    assert @object.has_property?('NaN')
    assert @object['NaN'].dont_enum?
    assert @object['NaN'].dont_delete?
    assert @object['NaN'].value.nan?
  end

  def test_global_nan
    js_assert_equal('Number.NaN', 'NaN')
  end

  def test_this_nan
    js_assert_equal('Number.NaN', 'this.NaN')
  end

  def test_typeof_nan
    js_assert_equal("'number'", 'typeof NaN')
  end
end
