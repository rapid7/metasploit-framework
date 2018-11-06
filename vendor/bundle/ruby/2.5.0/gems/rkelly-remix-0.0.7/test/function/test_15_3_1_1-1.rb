require File.dirname(__FILE__) + "/../helper"

class Functions_15_3_1_1_1_Test < ECMAScriptTestCase
  def setup
    super
    @runtime.execute(<<END
var MyObject = Function( "value", "this.value = value; this.valueOf =  Function( 'return this.value' ); this.toString =  Function( 'return String(this.value
);' )" );
var myfunc = Function();
myfunc.toString = Object.prototype.toString;
END
                    )
  end

  def test_to_string
    js_assert_equal("'[object Function]'", "myfunc.toString()")
  end

  def test_length
    js_assert_equal("0", "myfunc.length")
  end

  def test_prototype_to_string
    js_assert_equal("'[object Object]'", "myfunc.prototype.toString()")
  end

  def test_prototype_constructor
    js_assert_equal("myfunc", "myfunc.prototype.constructor")
  end

  def test_arguments
    js_assert_equal("null", "myfunc.arguments")
  end
end
