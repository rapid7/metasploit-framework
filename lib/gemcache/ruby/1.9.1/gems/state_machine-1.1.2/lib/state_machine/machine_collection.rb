require 'state_machine/assertions'

module StateMachine
  # Represents a collection of state machines for a class
  class MachineCollection < Hash
    include Assertions
    
    # Initializes the state of each machine in the given object.  This can allow
    # states to be initialized in two groups: static and dynamic.  For example:
    # 
    #   machines.initialize_states(object) do
    #     # After static state initialization, before dynamic state initialization
    #   end
    # 
    # If no block is provided, then all states will still be initialized.
    # 
    # Valid configuration options:
    # * <tt>:static</tt> - Whether to initialize static states.  If set to
    #   :force, the state will be initialized regardless of its current value.
    #   Default is :force.
    # * <tt>:dynamic</tt> - Whether to initialize dynamic states.  If set to
    #   :force, the state will be initialized regardless of its current value.
    #   Default is true.
    # * <tt>:to</tt> - A hash to write the initialized state to instead of
    #   writing to the object.  Default is to write directly to the object.
    def initialize_states(object, options = {})
      assert_valid_keys(options, :static, :dynamic, :to)
      options = {:static => :force, :dynamic => true}.merge(options)
      
      each_value do |machine| 
        machine.initialize_state(object, :force => options[:static] == :force, :to => options[:to]) unless machine.dynamic_initial_state?
      end if options[:static]
      
      result = yield if block_given?
      
      each_value do |machine|
        machine.initialize_state(object, :force => options[:dynamic] == :force, :to => options[:to]) if machine.dynamic_initial_state?
      end if options[:dynamic]
      
      result
    end
    
    # Runs one or more events in parallel on the given object.  See
    # StateMachine::InstanceMethods#fire_events for more information.
    def fire_events(object, *events)
      run_action = [true, false].include?(events.last) ? events.pop : true
      
      # Generate the transitions to run for each event
      transitions = events.collect do |event_name|
        # Find the actual event being run
        event = nil
        detect {|name, machine| event = machine.events[event_name, :qualified_name]}
        
        raise(InvalidEvent.new(object, event_name)) unless event
        
        # Get the transition that will be performed for the event
        unless transition = event.transition_for(object)
          machine = event.machine
          event.on_failure(object)
        end
        
        transition
      end.compact
      
      # Run the events in parallel only if valid transitions were found for
      # all of them
      if events.length == transitions.length
        TransitionCollection.new(transitions, :actions => run_action).perform
      else
        false
      end
    end
    
    # Builds the collection of transitions for all event attributes defined on
    # the given object.  This will only include events whose machine actions
    # match the one specified.
    # 
    # These should only be fired as a result of the action being run.
    def transitions(object, action, options = {})
      transitions = map do |name, machine|
        machine.events.attribute_transition_for(object, true) if machine.action == action
      end
      
      AttributeTransitionCollection.new(transitions.compact, options)
    end
  end
end
