require File.expand_path(File.dirname(__FILE__) + '/../test_helper')

class CallbackTest < Test::Unit::TestCase
  def test_should_raise_exception_if_invalid_type_specified
    exception = assert_raise(ArgumentError) { StateMachine::Callback.new(:invalid) {} }
    assert_equal 'Type must be :before, :after, :around, or :failure', exception.message
  end
  
  def test_should_not_raise_exception_if_using_before_type
    assert_nothing_raised { StateMachine::Callback.new(:before) {} }
  end
  
  def test_should_not_raise_exception_if_using_after_type
    assert_nothing_raised { StateMachine::Callback.new(:after) {} }
  end
  
  def test_should_not_raise_exception_if_using_around_type
    assert_nothing_raised { StateMachine::Callback.new(:around) {} }
  end
  
  def test_should_not_raise_exception_if_using_failure_type
    assert_nothing_raised { StateMachine::Callback.new(:failure) {} }
  end
  
  def test_should_raise_exception_if_no_methods_specified
    exception = assert_raise(ArgumentError) { StateMachine::Callback.new(:before) }
    assert_equal 'Method(s) for callback must be specified', exception.message
  end
  
  def test_should_not_raise_exception_if_method_specified_in_do_option
    assert_nothing_raised { StateMachine::Callback.new(:before, :do => :run) }
  end
  
  def test_should_not_raise_exception_if_method_specified_as_argument
    assert_nothing_raised { StateMachine::Callback.new(:before, :run) }
  end
  
  def test_should_not_raise_exception_if_method_specified_as_block
    assert_nothing_raised { StateMachine::Callback.new(:before, :run) {} }
  end
  
  def test_should_not_raise_exception_if_implicit_option_specified
    assert_nothing_raised { StateMachine::Callback.new(:before, :do => :run, :invalid => :valid) }
  end
  
  def test_should_not_bind_to_objects
    assert !StateMachine::Callback.bind_to_object
  end
  
  def test_should_not_have_a_terminator
    assert_nil StateMachine::Callback.terminator
  end
end

class CallbackByDefaultTest < Test::Unit::TestCase
  def setup
    @callback = StateMachine::Callback.new(:before) {}
  end
  
  def test_should_have_type
    assert_equal :before, @callback.type
  end
  
  def test_should_not_have_a_terminator
    assert_nil @callback.terminator
  end
  
  def test_should_have_a_branch_with_all_matcher_requirements
    assert_equal StateMachine::AllMatcher.instance, @callback.branch.event_requirement
    assert_equal StateMachine::AllMatcher.instance, @callback.branch.state_requirements.first[:from]
    assert_equal StateMachine::AllMatcher.instance, @callback.branch.state_requirements.first[:to]
  end
  
  def test_should_not_have_any_known_states
    assert_equal [], @callback.known_states
  end
end

class CallbackWithMethodArgumentTest < Test::Unit::TestCase
  def setup
    @callback = StateMachine::Callback.new(:before, lambda {|*args| @args = args})
    
    @object = Object.new
    @result = @callback.call(@object)
  end
  
  def test_should_be_successful
    assert @result
  end
  
  def test_should_call_with_empty_context
    assert_equal [@object], @args
  end
end

class CallbackWithMultipleMethodArgumentsTest < Test::Unit::TestCase
  def setup
    @callback = StateMachine::Callback.new(:before, :run_1, :run_2)
    
    class << @object = Object.new
      attr_accessor :callbacks
      
      def run_1
        (@callbacks ||= []) << :run_1
      end
      
      def run_2
        (@callbacks ||= []) << :run_2
      end
    end
    
    @result = @callback.call(@object)
  end
  
  def test_should_be_successful
    assert @result
  end
  
  def test_should_call_each_callback_in_order
    assert_equal [:run_1, :run_2], @object.callbacks
  end
end

class CallbackWithDoMethodTest < Test::Unit::TestCase
  def setup
    @callback = StateMachine::Callback.new(:before, :do => lambda {|*args| @args = args})
    
    @object = Object.new
    @result = @callback.call(@object)
  end
  
  def test_should_be_successful
    assert @result
  end
  
  def test_should_call_with_empty_context
    assert_equal [@object], @args
  end
end

class CallbackWithMultipleDoMethodsTest < Test::Unit::TestCase
  def setup
    @callback = StateMachine::Callback.new(:before, :do => [:run_1, :run_2])
    
    class << @object = Object.new
      attr_accessor :callbacks
      
      def run_1
        (@callbacks ||= []) << :run_1
      end
      
      def run_2
        (@callbacks ||= []) << :run_2
      end
    end
    
    @result = @callback.call(@object)
  end
  
  def test_should_be_successful
    assert @result
  end
  
  def test_should_call_each_callback_in_order
    assert_equal [:run_1, :run_2], @object.callbacks
  end
end

class CallbackWithBlockTest < Test::Unit::TestCase
  def setup
    @callback = StateMachine::Callback.new(:before) do |*args|
      @args = args
    end
    
    @object = Object.new
    @result = @callback.call(@object)
  end
  
  def test_should_be_successful
    assert @result
  end
  
  def test_should_call_with_empty_context
    assert_equal [@object], @args
  end
end

class CallbackWithMixedMethodsTest < Test::Unit::TestCase
  def setup
    @callback = StateMachine::Callback.new(:before, :run_argument, :do => :run_do) do |object|
      object.callbacks << :block
    end
    
    class << @object = Object.new
      attr_accessor :callbacks
      
      def run_argument
        (@callbacks ||= []) << :argument
      end
      
      def run_do
        (@callbacks ||= []) << :do
      end
    end
    
    @result = @callback.call(@object)
  end
  
  def test_should_be_successful
    assert @result
  end
  
  def test_should_call_each_callback_in_order
    assert_equal [:argument, :do, :block], @object.callbacks
  end
end

class CallbackWithExplicitRequirementsTest < Test::Unit::TestCase
  def setup
    @object = Object.new
    @callback = StateMachine::Callback.new(:before, :from => :parked, :to => :idling, :on => :ignite, :do => lambda {})
  end
  
  def test_should_call_with_empty_context
    assert @callback.call(@object, {})
  end
  
  def test_should_not_call_if_from_not_included
    assert !@callback.call(@object, :from => :idling)
  end
  
  def test_should_not_call_if_to_not_included
    assert !@callback.call(@object, :to => :parked)
  end
  
  def test_should_not_call_if_on_not_included
    assert !@callback.call(@object, :on => :park)
  end
  
  def test_should_call_if_all_requirements_met
    assert @callback.call(@object, :from => :parked, :to => :idling, :on => :ignite)
  end
  
  def test_should_include_in_known_states
    assert_equal [:parked, :idling], @callback.known_states
  end
end

class CallbackWithImplicitRequirementsTest < Test::Unit::TestCase
  def setup
    @object = Object.new
    @callback = StateMachine::Callback.new(:before, :parked => :idling, :on => :ignite, :do => lambda {})
  end
  
  def test_should_call_with_empty_context
    assert @callback.call(@object, {})
  end
  
  def test_should_not_call_if_from_not_included
    assert !@callback.call(@object, :from => :idling)
  end
  
  def test_should_not_call_if_to_not_included
    assert !@callback.call(@object, :to => :parked)
  end
  
  def test_should_not_call_if_on_not_included
    assert !@callback.call(@object, :on => :park)
  end
  
  def test_should_call_if_all_requirements_met
    assert @callback.call(@object, :from => :parked, :to => :idling, :on => :ignite)
  end
  
  def test_should_include_in_known_states
    assert_equal [:parked, :idling], @callback.known_states
  end
end

class CallbackWithIfConditionTest < Test::Unit::TestCase
  def setup
    @object = Object.new
  end
  
  def test_should_call_if_true
    callback = StateMachine::Callback.new(:before, :if => lambda {true}, :do => lambda {})
    assert callback.call(@object)
  end
  
  def test_should_not_call_if_false
    callback = StateMachine::Callback.new(:before, :if => lambda {false}, :do => lambda {})
    assert !callback.call(@object)
  end
end

class CallbackWithUnlessConditionTest < Test::Unit::TestCase
  def setup
    @object = Object.new
  end
  
  def test_should_call_if_false
    callback = StateMachine::Callback.new(:before, :unless => lambda {false}, :do => lambda {})
    assert callback.call(@object)
  end
  
  def test_should_not_call_if_true
    callback = StateMachine::Callback.new(:before, :unless => lambda {true}, :do => lambda {})
    assert !callback.call(@object)
  end
end

class CallbackWithoutTerminatorTest < Test::Unit::TestCase
  def setup
    @object = Object.new
  end
  
  def test_should_not_halt_if_result_is_false
    callback = StateMachine::Callback.new(:before, :do => lambda {false}, :terminator => nil)
    assert_nothing_thrown { callback.call(@object) }
  end
end

class CallbackWithTerminatorTest < Test::Unit::TestCase
  def setup
    @object = Object.new
  end
  
  def test_should_not_halt_if_terminator_does_not_match
    callback = StateMachine::Callback.new(:before, :do => lambda {false}, :terminator => lambda {|result| result == true})
    assert_nothing_thrown { callback.call(@object) }
  end
  
  def test_should_halt_if_terminator_matches
    callback = StateMachine::Callback.new(:before, :do => lambda {false}, :terminator => lambda {|result| result == false})
    assert_throws(:halt) { callback.call(@object) }
  end
  
  def test_should_halt_if_terminator_matches_any_method
    callback = StateMachine::Callback.new(:before, :do => [lambda {true}, lambda {false}], :terminator => lambda {|result| result == false})
    assert_throws(:halt) { callback.call(@object) }
  end
end

class CallbackWithoutArgumentsTest < Test::Unit::TestCase
  def setup
    @callback = StateMachine::Callback.new(:before, :do => lambda {|object| @arg = object})
    
    @object = Object.new
    @callback.call(@object, {}, 1, 2, 3)
  end
  
  def test_should_call_method_with_object_as_argument
    assert_equal @object, @arg
  end
end

class CallbackWithArgumentsTest < Test::Unit::TestCase
  def setup
    @callback = StateMachine::Callback.new(:before, :do => lambda {|*args| @args = args})
    
    @object = Object.new
    @callback.call(@object, {}, 1, 2, 3)
  end
  
  def test_should_call_method_with_all_arguments
    assert_equal [@object, 1, 2, 3], @args
  end
end

class CallbackWithUnboundMethodTest < Test::Unit::TestCase
  def setup
    @callback = StateMachine::Callback.new(:before, :do => lambda {|*args| @context = args.unshift(self)})
    
    @object = Object.new
    @callback.call(@object, {}, 1, 2, 3)
  end
  
  def test_should_call_method_outside_the_context_of_the_object
    assert_equal [self, @object, 1, 2, 3], @context
  end
end

class CallbackWithBoundMethodTest < Test::Unit::TestCase
  def setup
    @object = Object.new
  end
  
  def test_should_call_method_within_the_context_of_the_object_for_block_methods
    context = nil
    callback = StateMachine::Callback.new(:before, :do => lambda {|*args| context = [self] + args}, :bind_to_object => true)
    callback.call(@object, {}, 1, 2, 3)
    
    assert_equal [@object, 1, 2, 3], context
  end
  
  def test_should_ignore_option_for_symbolic_methods
    class << @object
      attr_reader :context
      
      def after_ignite(*args)
        @context = args
      end
    end
    
    callback = StateMachine::Callback.new(:before, :do => :after_ignite, :bind_to_object => true)
    callback.call(@object)
    
    assert_equal [], @object.context
  end
  
  def test_should_ignore_option_for_string_methods
    callback = StateMachine::Callback.new(:before, :do => '[1, 2, 3]', :bind_to_object => true)
    assert callback.call(@object)
  end
end

class CallbackWithMultipleBoundMethodsTest < Test::Unit::TestCase
  def setup
    @object = Object.new
    
    first_context = nil
    second_context = nil
    
    @callback = StateMachine::Callback.new(:before, :do => [lambda {first_context = self}, lambda {second_context = self}], :bind_to_object => true)
    @callback.call(@object)
    
    @first_context = first_context
    @second_context = second_context
  end
  
  def test_should_call_each_method_within_the_context_of_the_object
    assert_equal @object, @first_context
    assert_equal @object, @second_context
  end
end

class CallbackWithApplicationBoundObjectTest < Test::Unit::TestCase
  def setup
    @original_bind_to_object = StateMachine::Callback.bind_to_object
    StateMachine::Callback.bind_to_object = true
    
    context = nil
    @callback = StateMachine::Callback.new(:before, :do => lambda {|*args| context = self})
    
    @object = Object.new
    @callback.call(@object)
    @context = context
  end
  
  def test_should_call_method_within_the_context_of_the_object
    assert_equal @object, @context
  end
  
  def teardown
    StateMachine::Callback.bind_to_object = @original_bind_to_object
  end
end

class CallbackWithBoundMethodAndArgumentsTest < Test::Unit::TestCase
  def setup
    @object = Object.new
  end
  
  def test_should_include_single_argument_if_specified
    context = nil
    callback = StateMachine::Callback.new(:before, :do => lambda {|arg1| context = [arg1]}, :bind_to_object => true)
    callback.call(@object, {}, 1)
    assert_equal [1], context
  end
  
  def test_should_include_multiple_arguments_if_specified
    context = nil
    callback = StateMachine::Callback.new(:before, :do => lambda {|arg1, arg2, arg3| context = [arg1, arg2, arg3]}, :bind_to_object => true)
    callback.call(@object, {}, 1, 2, 3)
    assert_equal [1, 2, 3], context
  end
  
  def test_should_include_arguments_if_splat_used
    context = nil
    callback = StateMachine::Callback.new(:before, :do => lambda {|*args| context = args}, :bind_to_object => true)
    callback.call(@object, {}, 1, 2, 3)
    assert_equal [1, 2, 3], context
  end
end

class CallbackWithApplicationTerminatorTest < Test::Unit::TestCase
  def setup
    @original_terminator = StateMachine::Callback.bind_to_object
    StateMachine::Callback.terminator = lambda {|result| result == false}
    
    @object = Object.new
  end
  
  def test_should_not_halt_if_terminator_does_not_match
    callback = StateMachine::Callback.new(:before, :do => lambda {true})
    assert_nothing_thrown { callback.call(@object) }
  end
  
  def test_should_halt_if_terminator_matches
    callback = StateMachine::Callback.new(:before, :do => lambda {false})
    assert_throws(:halt) { callback.call(@object) }
  end
  
  def teardown
    StateMachine::Callback.bind_to_object = @original_bind_to_object
  end
end

class CallbackWithAroundTypeAndBlockTest < Test::Unit::TestCase
  def setup
    @object = Object.new
    @callbacks = []
  end
  
  def test_should_evaluate_before_without_after
    callback = StateMachine::Callback.new(:around, lambda {|*args| block = args.pop; @args = args; block.call})
    assert callback.call(@object)
    assert_equal [@object], @args
  end
  
  def test_should_evaluate_after_without_before
    callback = StateMachine::Callback.new(:around, lambda {|*args| block = args.pop; block.call; @args = args})
    assert callback.call(@object)
    assert_equal [@object], @args
  end
  
  def test_should_halt_if_not_yielded
    callback = StateMachine::Callback.new(:around, lambda {|block|})
    assert_throws(:halt) { callback.call(@object) }
  end
  
  def test_should_call_block_after_before
    callback = StateMachine::Callback.new(:around, lambda {|block| @callbacks << :before; block.call})
    assert callback.call(@object) { @callbacks << :block }
    assert_equal [:before, :block], @callbacks
  end
  
  def test_should_call_block_before_after
    @callbacks = []
    callback = StateMachine::Callback.new(:around, lambda {|block| block.call; @callbacks << :after})
    assert callback.call(@object) { @callbacks << :block }
    assert_equal [:block, :after], @callbacks
  end
  
  def test_should_halt_if_block_halts
    callback = StateMachine::Callback.new(:around, lambda {|block| block.call; @callbacks << :after})
    assert_throws(:halt) { callback.call(@object) { throw :halt }  }
    assert_equal [], @callbacks
  end
end

class CallbackWithAroundTypeAndMultipleMethodsTest < Test::Unit::TestCase
  def setup
    @callback = StateMachine::Callback.new(:around, :run_1, :run_2)
    
    class << @object = Object.new
      attr_accessor :before_callbacks
      attr_accessor :after_callbacks
      
      def run_1
        (@before_callbacks ||= []) << :run_1
        yield
        (@after_callbacks ||= []) << :run_1
      end
      
      def run_2
        (@before_callbacks ||= []) << :run_2
        yield
        (@after_callbacks ||= []) << :run_2
      end
    end
  end
  
  def test_should_succeed
    assert @callback.call(@object)
  end
  
  def test_should_evaluate_before_callbacks_in_order
    @callback.call(@object)
    assert_equal [:run_1, :run_2], @object.before_callbacks
  end
  
  def test_should_evaluate_after_callbacks_in_reverse_order
    @callback.call(@object)
    assert_equal [:run_2, :run_1], @object.after_callbacks
  end
  
  def test_should_call_block_after_before_callbacks
    @callback.call(@object) { (@object.before_callbacks ||= []) << :block }
    assert_equal [:run_1, :run_2, :block], @object.before_callbacks
  end
  
  def test_should_call_block_before_after_callbacks
    @callback.call(@object) { (@object.after_callbacks ||= []) << :block }
    assert_equal [:block, :run_2, :run_1], @object.after_callbacks
  end
  
  def test_should_halt_if_first_doesnt_yield
    class << @object
      def run_1
        (@before_callbacks ||= []) << :run_1
      end
    end
    
    catch(:halt) do
      @callback.call(@object) { (@object.before_callbacks ||= []) << :block }
    end
    
    assert_equal [:run_1], @object.before_callbacks
    assert_nil @object.after_callbacks
  end
  
  def test_should_halt_if_last_doesnt_yield
    class << @object
      def run_2
        (@before_callbacks ||= []) << :run_2
      end
    end
    
    catch(:halt) { @callback.call(@object) }
    assert_equal [:run_1, :run_2], @object.before_callbacks
    assert_nil @object.after_callbacks
  end
  
  def test_should_not_evaluate_further_methods_if_after_halts
    class << @object
      def run_2
        (@before_callbacks ||= []) << :run_2
        yield
        (@after_callbacks ||= []) << :run_2
        throw :halt
      end
    end
    
    catch(:halt) { @callback.call(@object) }
    assert_equal [:run_1, :run_2], @object.before_callbacks
    assert_equal [:run_2], @object.after_callbacks
  end
end

class CallbackWithAroundTypeAndArgumentsTest < Test::Unit::TestCase
  def setup
    @object = Object.new
  end
  
  def test_should_include_object_if_specified
    callback = StateMachine::Callback.new(:around, lambda {|object, block| @args = [object]; block.call})
    callback.call(@object)
    assert_equal [@object], @args
  end
  
  def test_should_include_arguments_if_specified
    callback = StateMachine::Callback.new(:around, lambda {|object, arg1, arg2, arg3, block| @args = [object, arg1, arg2, arg3]; block.call})
    callback.call(@object, {}, 1, 2, 3)
    assert_equal [@object, 1, 2, 3], @args
  end
  
  def test_should_include_arguments_if_splat_used
    callback = StateMachine::Callback.new(:around, lambda {|*args| block = args.pop; @args = args; block.call})
    callback.call(@object, {}, 1, 2, 3)
    assert_equal [@object, 1, 2, 3], @args
  end
end

class CallbackWithAroundTypeAndTerminatorTest < Test::Unit::TestCase
  def setup
    @object = Object.new
  end
  
  def test_should_not_halt_if_terminator_does_not_match
    callback = StateMachine::Callback.new(:around, :do => lambda {|block| block.call(false); false}, :terminator => lambda {|result| result == true})
    assert_nothing_thrown { callback.call(@object) }
  end
  
  def test_should_not_halt_if_terminator_matches
    callback = StateMachine::Callback.new(:around, :do => lambda {|block| block.call(false); false}, :terminator => lambda {|result| result == false})
    assert_nothing_thrown { callback.call(@object) }
  end
end

class CallbackWithAroundTypeAndBoundMethodTest < Test::Unit::TestCase
  def setup
    @object = Object.new
  end
  
  def test_should_call_method_within_the_context_of_the_object
    context = nil
    callback = StateMachine::Callback.new(:around, :do => lambda {|block| context = self; block.call}, :bind_to_object => true)
    callback.call(@object, {}, 1, 2, 3)
    
    assert_equal @object, context
  end
  
  def test_should_include_arguments_if_specified
    context = nil
    callback = StateMachine::Callback.new(:around, :do => lambda {|*args| block = args.pop; context = args; block.call}, :bind_to_object => true)
    callback.call(@object, {}, 1, 2, 3)
    
    assert_equal [1, 2, 3], context
  end
end
