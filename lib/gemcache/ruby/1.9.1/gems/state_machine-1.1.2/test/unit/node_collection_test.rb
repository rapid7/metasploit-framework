require File.expand_path(File.dirname(__FILE__) + '/../test_helper')

class Node < Struct.new(:name, :value, :machine)
  def context
    yield
  end
end

class NodeCollectionByDefaultTest < Test::Unit::TestCase
  def setup
    @machine = StateMachine::Machine.new(Class.new)
    @collection = StateMachine::NodeCollection.new(@machine)
  end
  
  def test_should_not_have_any_nodes
    assert_equal 0, @collection.length
  end
  
  def test_should_have_a_machine
    assert_equal @machine, @collection.machine
  end
  
  def test_should_index_by_name
    @collection << object = Node.new(:parked)
    assert_equal object, @collection[:parked]
  end
end

class NodeCollectionTest < Test::Unit::TestCase
  def setup
    @machine = StateMachine::Machine.new(Class.new)
    @collection = StateMachine::NodeCollection.new(@machine)
  end
  
  def test_should_raise_exception_if_invalid_option_specified
    exception = assert_raise(ArgumentError) { StateMachine::NodeCollection.new(@machine, :invalid => true) }
    assert_equal 'Invalid key(s): invalid', exception.message
  end
  
  def test_should_raise_exception_on_lookup_if_invalid_index_specified
    exception = assert_raise(ArgumentError) { @collection[:something, :invalid] }
    assert_equal 'Invalid index: :invalid', exception.message
  end
  
  def test_should_raise_exception_on_fetch_if_invalid_index_specified
    exception = assert_raise(ArgumentError) { @collection.fetch(:something, :invalid) }
    assert_equal 'Invalid index: :invalid', exception.message
  end
end

class NodeCollectionAfterBeingCopiedTest < Test::Unit::TestCase
  def setup
    machine = StateMachine::Machine.new(Class.new)
    @collection = StateMachine::NodeCollection.new(machine)
    @collection << @parked = Node.new(:parked)
    
    @contexts_run = contexts_run = []
    @collection.context([:parked]) {contexts_run << :parked}
    @contexts_run.clear
    
    @copied_collection = @collection.dup
    @copied_collection << @idling = Node.new(:idling)
    @copied_collection.context([:first_gear]) {contexts_run << :first_gear}
  end
  
  def test_should_not_modify_the_original_list
    assert_equal 1, @collection.length
    assert_equal 2, @copied_collection.length
  end
  
  def test_should_not_modify_the_indices
    assert_nil @collection[:idling]
    assert_equal @idling, @copied_collection[:idling]
  end
  
  def test_should_copy_each_node
    assert_not_same @parked, @copied_collection[:parked]
  end
  
  def test_should_not_run_contexts
    assert_equal [], @contexts_run
  end
  
  def test_should_not_modify_contexts
    @collection << Node.new(:first_gear)
    assert_equal [], @contexts_run
  end
  
  def test_should_copy_contexts
    @copied_collection << Node.new(:parked)
    assert !@contexts_run.empty?
  end
end

class NodeCollectionWithoutIndicesTest < Test::Unit::TestCase
  def setup
    machine = StateMachine::Machine.new(Class.new)
    @collection = StateMachine::NodeCollection.new(machine, :index => {})
  end
  
  def test_should_allow_adding_node
    @collection << Object.new
    assert_equal 1, @collection.length
  end
  
  def test_should_not_allow_keys_retrieval
    exception = assert_raise(ArgumentError) { @collection.keys }
    assert_equal 'No indices configured', exception.message
  end
  
  def test_should_not_allow_lookup
    @collection << object = Object.new
    exception = assert_raise(ArgumentError) { @collection[0] }
    assert_equal 'No indices configured', exception.message
  end
  
  def test_should_not_allow_fetching
    @collection << object = Object.new
    exception = assert_raise(ArgumentError) { @collection.fetch(0) }
    assert_equal 'No indices configured', exception.message
  end
end

class NodeCollectionWithIndicesTest < Test::Unit::TestCase
  def setup
    machine = StateMachine::Machine.new(Class.new)
    @collection = StateMachine::NodeCollection.new(machine, :index => [:name, :value])
    
    @object = Node.new(:parked, 1)
    @collection << @object
  end
  
  def test_should_use_first_index_by_default_on_key_retrieval
    assert_equal [:parked], @collection.keys
  end
  
  def test_should_allow_customizing_index_for_key_retrieval
    assert_equal [1], @collection.keys(:value)
  end
  
  def test_should_use_first_index_by_default_on_lookup
    assert_equal @object, @collection[:parked]
    assert_nil @collection[1]
  end
  
  def test_should_allow_customizing_index_on_lookup
    assert_equal @object, @collection[1, :value]
    assert_nil @collection[:parked, :value]
  end
  
  def test_should_use_first_index_by_default_on_fetch
    assert_equal @object, @collection.fetch(:parked)
    exception = assert_raise(IndexError) { @collection.fetch(1) }
    assert_equal '1 is an invalid name', exception.message
  end
  
  def test_should_allow_customizing_index_on_fetch
    assert_equal @object, @collection.fetch(1, :value)
    exception = assert_raise(IndexError) { @collection.fetch(:parked, :value) }
    assert_equal ':parked is an invalid value', exception.message
  end
end

class NodeCollectionWithNodesTest < Test::Unit::TestCase
  def setup
    @machine = StateMachine::Machine.new(Class.new)
    @collection = StateMachine::NodeCollection.new(@machine)
    
    @parked = Node.new(:parked, nil, @machine)
    @idling = Node.new(:idling, nil, @machine)
    
    @collection << @parked
    @collection << @idling
  end
  
  def test_should_be_able_to_enumerate
    order = []
    @collection.each {|object| order << object}
    
    assert_equal [@parked, @idling], order
  end
  
  def test_should_be_able_to_concatenate_multiple_nodes
    @first_gear = Node.new(:first_gear, nil, @machine)
    @second_gear = Node.new(:second_gear, nil, @machine)
    @collection.concat([@first_gear, @second_gear])
    
    order = []
    @collection.each {|object| order << object}
    assert_equal [@parked, @idling, @first_gear, @second_gear], order
  end
  
  def test_should_be_able_to_access_by_index
    assert_equal @parked, @collection.at(0)
    assert_equal @idling, @collection.at(1)
  end
  
  def test_should_deep_copy_machine_changes
    new_machine = StateMachine::Machine.new(Class.new)
    @collection.machine = new_machine
    
    assert_equal new_machine, @collection.machine
    assert_equal new_machine, @parked.machine
    assert_equal new_machine, @idling.machine
  end
end

class NodeCollectionAfterUpdateTest < Test::Unit::TestCase
  def setup
    machine = StateMachine::Machine.new(Class.new)
    @collection = StateMachine::NodeCollection.new(machine, :index => [:name, :value])
    
    @parked = Node.new(:parked, 1)
    @idling = Node.new(:idling, 2)
    
    @collection << @parked << @idling
    
    @parked.name = :parking
    @parked.value = 0
    @collection.update(@parked)
  end
  
  def test_should_not_change_the_index
    assert_equal @parked, @collection.at(0)
  end
  
  def test_should_not_duplicate_in_the_collection
    assert_equal 2, @collection.length
  end
  
  def test_should_add_each_indexed_key
    assert_equal @parked, @collection[:parking]
    assert_equal @parked, @collection[0, :value]
  end
  
  def test_should_remove_each_old_indexed_key
    assert_nil @collection[:parked]
    assert_nil @collection[1, :value]
  end
end

class NodeCollectionWithStringIndexTest < Test::Unit::TestCase
  def setup
    machine = StateMachine::Machine.new(Class.new)
    @collection = StateMachine::NodeCollection.new(machine, :index => [:name, :value])
    
    @parked = Node.new(:parked, 1)
    @collection << @parked
  end
  
  def test_should_index_by_name
    assert_equal @parked, @collection[:parked]
  end
  
  def test_should_index_by_string_name
    assert_equal @parked, @collection['parked']
  end
end

class NodeCollectionWithSymbolIndexTest < Test::Unit::TestCase
  def setup
    machine = StateMachine::Machine.new(Class.new)
    @collection = StateMachine::NodeCollection.new(machine, :index => [:name, :value])
    
    @parked = Node.new('parked', 1)
    @collection << @parked
  end
  
  def test_should_index_by_name
    assert_equal @parked, @collection['parked']
  end
  
  def test_should_index_by_symbol_name
    assert_equal @parked, @collection[:parked]
  end
end

class NodeCollectionWithNumericIndexTest < Test::Unit::TestCase
  def setup
    machine = StateMachine::Machine.new(Class.new)
    @collection = StateMachine::NodeCollection.new(machine, :index => [:name, :value])
    
    @parked = Node.new(10, 1)
    @collection << @parked
  end
  
  def test_should_index_by_name
    assert_equal @parked, @collection[10]
  end
  
  def test_should_index_by_string_name
    assert_equal @parked, @collection['10']
  end
  
  def test_should_index_by_symbol_name
    assert_equal @parked, @collection[:'10']
  end
end

class NodeCollectionWithPredefinedContextsTest < Test::Unit::TestCase
  def setup
    machine = StateMachine::Machine.new(Class.new)
    @collection = StateMachine::NodeCollection.new(machine)
    
    @contexts_run = contexts_run = []
    @collection.context([:parked]) { contexts_run << :parked }
    @collection.context([:parked]) { contexts_run << :second_parked }
  end
  
  def test_should_run_contexts_in_the_order_defined
    @collection << Node.new(:parked)
    assert_equal [:parked, :second_parked], @contexts_run
  end
  
  def test_should_not_run_contexts_if_not_matched
    @collection << Node.new(:idling)
    assert_equal [], @contexts_run
  end
end

class NodeCollectionWithPostdefinedContextsTest < Test::Unit::TestCase
  def setup
    machine = StateMachine::Machine.new(Class.new)
    @collection = StateMachine::NodeCollection.new(machine)
    @collection << Node.new(:parked)
  end
  
  def test_should_run_context_if_matched
    contexts_run = []
    @collection.context([:parked]) { contexts_run << :parked }
    assert_equal [:parked], contexts_run
  end
  
  def test_should_not_run_contexts_if_not_matched
    contexts_run = []
    @collection.context([:idling]) { contexts_run << :idling }
    assert_equal [], contexts_run
  end
end

class NodeCollectionWithMatcherContextsTest < Test::Unit::TestCase
  def setup
    machine = StateMachine::Machine.new(Class.new)
    @collection = StateMachine::NodeCollection.new(machine)
    @collection << Node.new(:parked)
  end
  
  def test_should_always_run_all_matcher_context
    contexts_run = []
    @collection.context([StateMachine::AllMatcher.instance]) { contexts_run << :all }
    assert_equal [:all], contexts_run
  end
  
  def test_should_only_run_blacklist_matcher_if_not_matched
    contexts_run = []
    @collection.context([StateMachine::BlacklistMatcher.new([:parked])]) { contexts_run << :blacklist }
    assert_equal [], contexts_run
    
    @collection << Node.new(:idling)
    assert_equal [:blacklist], contexts_run
  end
end
