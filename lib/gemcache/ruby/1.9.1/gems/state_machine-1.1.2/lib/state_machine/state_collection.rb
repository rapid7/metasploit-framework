require 'state_machine/node_collection'

module StateMachine
  # Represents a collection of states in a state machine
  class StateCollection < NodeCollection
    def initialize(machine) #:nodoc:
      super(machine, :index => [:name, :qualified_name, :value])
    end
    
    # Determines whether the given object is in a specific state.  If the
    # object's current value doesn't match the state, then this will return
    # false, otherwise true.  If the given state is unknown, then an IndexError
    # will be raised.
    # 
    # == Examples
    # 
    #   class Vehicle
    #     state_machine :initial => :parked do
    #       other_states :idling
    #     end
    #   end
    #   
    #   states = Vehicle.state_machine.states
    #   vehicle = Vehicle.new               # => #<Vehicle:0xb7c464b0 @state="parked">
    #   
    #   states.matches?(vehicle, :parked)   # => true
    #   states.matches?(vehicle, :idling)   # => false
    #   states.matches?(vehicle, :invalid)  # => IndexError: :invalid is an invalid key for :name index
    def matches?(object, name)
      fetch(name).matches?(machine.read(object, :state))
    end
    
    # Determines the current state of the given object as configured by this
    # state machine.  This will attempt to find a known state that matches
    # the value of the attribute on the object.
    # 
    # == Examples
    # 
    #   class Vehicle
    #     state_machine :initial => :parked do
    #       other_states :idling
    #     end
    #   end
    #   
    #   states = Vehicle.state_machine.states
    #   
    #   vehicle = Vehicle.new         # => #<Vehicle:0xb7c464b0 @state="parked">
    #   states.match(vehicle)         # => #<StateMachine::State name=:parked value="parked" initial=true>
    #   
    #   vehicle.state = 'idling'
    #   states.match(vehicle)         # => #<StateMachine::State name=:idling value="idling" initial=true>
    #   
    #   vehicle.state = 'invalid'
    #   states.match(vehicle)         # => nil
    def match(object)
      value = machine.read(object, :state)
      self[value, :value] || detect {|state| state.matches?(value)}
    end
    
    # Determines the current state of the given object as configured by this
    # state machine.  If no state is found, then an ArgumentError will be
    # raised.
    # 
    # == Examples
    # 
    #   class Vehicle
    #     state_machine :initial => :parked do
    #       other_states :idling
    #     end
    #   end
    #   
    #   states = Vehicle.state_machine.states
    #   
    #   vehicle = Vehicle.new         # => #<Vehicle:0xb7c464b0 @state="parked">
    #   states.match!(vehicle)        # => #<StateMachine::State name=:parked value="parked" initial=true>
    #   
    #   vehicle.state = 'invalid'
    #   states.match!(vehicle)        # => ArgumentError: "invalid" is not a known state value
    def match!(object)
      match(object) || raise(ArgumentError, "#{machine.read(object, :state).inspect} is not a known #{machine.name} value")
    end
    
    # Gets the order in which states should be displayed based on where they
    # were first referenced.  This will order states in the following priority:
    # 
    # 1. Initial state
    # 2. Event transitions (:from, :except_from, :to, :except_to options)
    # 3. States with behaviors
    # 4. States referenced via +state+ or +other_states+
    # 5. States referenced in callbacks
    # 
    # This order will determine how the GraphViz visualizations are rendered.
    def by_priority
      order = select {|state| state.initial}.map {|state| state.name}
      
      machine.events.each {|event| order += event.known_states}
      order += select {|state| state.methods.any?}.map {|state| state.name}
      order += keys(:name) - machine.callbacks.values.flatten.map {|callback| callback.known_states}.flatten
      order += keys(:name)
      
      order.uniq!
      order.map! {|name| self[name]}
      order
    end
    
    private
      # Gets the value for the given attribute on the node
      def value(node, attribute)
        attribute == :value ? node.value(false) : super
      end
  end
end
