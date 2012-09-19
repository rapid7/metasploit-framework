require File.expand_path(File.dirname(__FILE__) + '/../test_helper')

class EvalHelpersBaseTest < Test::Unit::TestCase
  include StateMachine::EvalHelpers
  
  def default_test
  end
end

class EvalHelpersTest < EvalHelpersBaseTest
  def setup
    @object = Object.new
  end
  
  def test_should_raise_exception_if_method_is_not_symbol_string_or_proc
    exception = assert_raise(ArgumentError) { evaluate_method(@object, 1) }
    assert_match /Methods must/, exception.message
  end
end

class EvalHelpersSymbolTest < EvalHelpersBaseTest
  def setup
    class << (@object = Object.new)
      def callback
        true
      end
    end
  end
  
  def test_should_call_method_on_object_with_no_arguments
    assert_equal true, evaluate_method(@object, :callback, 1, 2, 3)
  end
end

class EvalHelpersSymbolProtectedTest < EvalHelpersBaseTest
  def setup
    class << (@object = Object.new)
      protected
      def callback
        true
      end
    end
  end
  
  def test_should_call_method_on_object_with_no_arguments
    assert_equal true, evaluate_method(@object, :callback, 1, 2, 3)
  end
end

class EvalHelpersSymbolPrivateTest < EvalHelpersBaseTest
  def setup
    class << (@object = Object.new)
      private
      def callback
        true
      end
    end
  end
  
  def test_should_call_method_on_object_with_no_arguments
    assert_equal true, evaluate_method(@object, :callback, 1, 2, 3)
  end
end

class EvalHelpersSymbolWithArgumentsTest < EvalHelpersBaseTest
  def setup
    class << (@object = Object.new)
      def callback(*args)
        args
      end
    end
  end
  
  def test_should_call_method_with_all_arguments
    assert_equal [1, 2, 3], evaluate_method(@object, :callback, 1, 2, 3)
  end
end

class EvalHelpersSymbolWithBlockTest < EvalHelpersBaseTest
  def setup
    class << (@object = Object.new)
      def callback
        yield
      end
    end
  end
  
  def test_should_call_method_on_object_with_block
    assert_equal true, evaluate_method(@object, :callback) { true }
  end
end

class EvalHelpersSymbolWithArgumentsAndBlockTest < EvalHelpersBaseTest
  def setup
    class << (@object = Object.new)
      def callback(*args)
        args << yield
      end
    end
  end
  
  def test_should_call_method_on_object_with_all_arguments_and_block
    assert_equal [1, 2, 3, true], evaluate_method(@object, :callback, 1, 2, 3) { true }
  end
end

class EvalHelpersSymbolTaintedMethodTest < EvalHelpersBaseTest
  def setup
    class << (@object = Object.new)
      def callback
        true
      end
      
      taint
    end
  end
  
  def test_should_not_raise_security_error
    assert_nothing_raised { evaluate_method(@object, :callback, 1, 2, 3) }
  end
end

class EvalHelpersSymbolMethodMissingTest < EvalHelpersBaseTest
  def setup
    class << (@object = Object.new)
      def method_missing(symbol, *args)
        send("method_missing_#{symbol}", *args)
      end
      
      def method_missing_callback(*args)
        args
      end
    end
  end
  
  def test_should_call_dynamic_method_with_all_arguments
    assert_equal [1, 2, 3], evaluate_method(@object, :callback, 1, 2, 3)
  end
end

class EvalHelpersStringTest < EvalHelpersBaseTest
  def setup
    @object = Object.new
  end
  
  def test_should_evaluate_string
    assert_equal 1, evaluate_method(@object, '1')
  end
  
  def test_should_evaluate_string_within_object_context
    @object.instance_variable_set('@value', 1)
    assert_equal 1, evaluate_method(@object, '@value')
  end
  
  def test_should_ignore_additional_arguments
    assert_equal 1, evaluate_method(@object, '1', 2, 3, 4)
  end
end

class EvalHelpersStringWithBlockTest < EvalHelpersBaseTest
  def setup
    @object = Object.new
  end
  
  def test_should_call_method_on_object_with_block
    assert_equal 1, evaluate_method(@object, 'yield') { 1 }
  end
end

class EvalHelpersProcTest < EvalHelpersBaseTest
  def setup
    @object = Object.new
    @proc = lambda {|obj| obj}
  end
  
  def test_should_call_proc_with_object_as_argument
    assert_equal @object, evaluate_method(@object, @proc, 1, 2, 3)
  end
end

class EvalHelpersProcWithoutArgumentsTest < EvalHelpersBaseTest
  def setup
    @object = Object.new
    @proc = lambda {|*args| args}
    class << @proc
      def arity
        0
      end
    end
  end
  
  def test_should_call_proc_with_no_arguments
    assert_equal [], evaluate_method(@object, @proc, 1, 2, 3)
  end
end

class EvalHelpersProcWithArgumentsTest < EvalHelpersBaseTest
  def setup
    @object = Object.new
    @proc = lambda {|*args| args}
  end
  
  def test_should_call_method_with_all_arguments
    assert_equal [@object, 1, 2, 3], evaluate_method(@object, @proc, 1, 2, 3)
  end
end

class EvalHelpersProcWithBlockTest < EvalHelpersBaseTest
  def setup
    @object = Object.new
    @proc = lambda {|obj, block| block.call}
  end
  
  def test_should_call_method_on_object_with_block
    assert_equal true, evaluate_method(@object, @proc, 1, 2, 3) { true }
  end
end

class EvalHelpersProcWithBlockWithoutArgumentsTest < EvalHelpersBaseTest
  def setup
    @object = Object.new
    @proc = lambda {|*args| args}
    class << @proc
      def arity
        0
      end
    end
  end
  
  def test_should_call_proc_without_arguments
    block = lambda { true }
    assert_equal [], evaluate_method(@object, @proc, 1, 2, 3, &block)
  end
end

class EvalHelpersProcWithBlockWithoutObjectTest < EvalHelpersBaseTest
  def setup
    @object = Object.new
    @proc = lambda {|block| [block]}
  end
  
  def test_should_call_proc_with_block_only
    block = lambda { true }
    assert_equal [block], evaluate_method(@object, @proc, 1, 2, 3, &block)
  end
end

class EvalHelpersProcBlockAndImplicitArgumentsTest < EvalHelpersBaseTest
  def setup
    @object = Object.new
    @proc = lambda {|*args| args}
  end
  
  def test_should_call_method_on_object_with_all_arguments_and_block
    block = lambda { true }
    assert_equal [@object, 1, 2, 3, block], evaluate_method(@object, @proc, 1, 2, 3, &block)
  end
end

class EvalHelpersProcBlockAndExplicitArgumentsTest < EvalHelpersBaseTest
  def setup
    @object = Object.new
    @proc = lambda {|object, arg1, arg2, arg3, block| [object, arg1, arg2, arg3, block]}
  end
  
  def test_should_call_method_on_object_with_all_arguments_and_block
    block = lambda { true }
    assert_equal [@object, 1, 2, 3, block], evaluate_method(@object, @proc, 1, 2, 3, &block)
  end
end
