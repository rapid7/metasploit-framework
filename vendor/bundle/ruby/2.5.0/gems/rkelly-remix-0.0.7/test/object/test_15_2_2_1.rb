require File.dirname(__FILE__) + "/../helper"

class Object_15_2_2_1_Test < ECMAScriptTestCase
  def test_null_typeof
    js_assert_equal("'object'", "typeof new Object(null)")
  end

  def test_null_to_string
    js_assert_to_string('Object', 'null')
  end

  def test_void_0_typeof
    js_assert_equal("'object'", "typeof new Object(void 0)")
  end

  def test_void_0_to_string
    js_assert_to_string('Object', 'void 0')
  end

  @@tests = {
    'minus_1'       => ['-1', 'Number'],
    '1'             => ['1', 'Number'],
    'minus_0'       => ['-0', 'Number'],
    '0'             => ['0', 'Number'],
    'nan'           => ['Number.NaN', 'Number'],
    'empty_string'  => ['""', 'String'],
    'string'        => ['"string"', 'String'],
    'true'          => ['true', 'Boolean'],
    'false'         => ['false', 'Boolean'],
    'boolean'       => ['Boolean()', 'Boolean'],
  }

  @@tests.each do |name, info|
    define_method(:"test_#{name}_typeof") do
      js_assert_equal("'object'", "typeof new Object(#{info[0]})")
    end
    define_method(:"test_#{name}_valueof") do
      js_assert_equal(info[0], "(new Object(#{info[0]})).valueOf()")
    end
    define_method(:"test_#{name}_tostring") do
      js_assert_to_string(info[1], info[0])
    end
  end

  def js_assert_to_string(expected_type, js_obj)
    @runtime.execute("
                     MYOB = new Object(#{js_obj});
                     MYOB.toString = Object.prototype.toString;
                     assert_equal('[object #{expected_type}]', MYOB.toString());
                     ")
  end
end
