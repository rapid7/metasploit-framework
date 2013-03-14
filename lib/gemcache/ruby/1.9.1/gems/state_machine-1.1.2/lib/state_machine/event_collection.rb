module StateMachine
  # Represents a collection of events in a state machine
  class EventCollection < NodeCollection
    def initialize(machine) #:nodoc:
      super(machine, :index => [:name, :qualified_name])
    end
    
    # Gets the list of events that can be fired on the given object.
    # 
    # Valid requirement options:
    # * <tt>:from</tt> - One or more states being transitioned from.  If none
    #   are specified, then this will be the object's current state.
    # * <tt>:to</tt> - One or more states being transitioned to.  If none are
    #   specified, then this will match any to state.
    # * <tt>:on</tt> - One or more events that fire the transition.  If none
    #   are specified, then this will match any event.
    # * <tt>:guard</tt> - Whether to guard transitions with the if/unless
    #   conditionals defined for each one.  Default is true.
    # 
    # == Examples
    # 
    #   class Vehicle
    #     state_machine :initial => :parked do
    #       event :park do
    #         transition :idling => :parked
    #       end
    #       
    #       event :ignite do
    #         transition :parked => :idling
    #       end
    #     end
    #   end
    #   
    #   events = Vehicle.state_machine(:state).events
    #   
    #   vehicle = Vehicle.new               # => #<Vehicle:0xb7c464b0 @state="parked">
    #   events.valid_for(vehicle)           # => [#<StateMachine::Event name=:ignite transitions=[:parked => :idling]>]
    #   
    #   vehicle.state = 'idling'
    #   events.valid_for(vehicle)           # => [#<StateMachine::Event name=:park transitions=[:idling => :parked]>]
    def valid_for(object, requirements = {})
      match(requirements).select {|event| event.can_fire?(object, requirements)}
    end
    
    # Gets the list of transitions that can be run on the given object.
    # 
    # Valid requirement options:
    # * <tt>:from</tt> - One or more states being transitioned from.  If none
    #   are specified, then this will be the object's current state.
    # * <tt>:to</tt> - One or more states being transitioned to.  If none are
    #   specified, then this will match any to state.
    # * <tt>:on</tt> - One or more events that fire the transition.  If none
    #   are specified, then this will match any event.
    # * <tt>:guard</tt> - Whether to guard transitions with the if/unless
    #   conditionals defined for each one.  Default is true.
    # 
    # == Examples
    # 
    #   class Vehicle
    #     state_machine :initial => :parked do
    #       event :park do
    #         transition :idling => :parked
    #       end
    #       
    #       event :ignite do
    #         transition :parked => :idling
    #       end
    #     end
    #   end
    #   
    #   events = Vehicle.state_machine.events
    #   
    #   vehicle = Vehicle.new                             # => #<Vehicle:0xb7c464b0 @state="parked">
    #   events.transitions_for(vehicle)                   # => [#<StateMachine::Transition attribute=:state event=:ignite from="parked" from_name=:parked to="idling" to_name=:idling>]
    #   
    #   vehicle.state = 'idling'
    #   events.transitions_for(vehicle)                   # => [#<StateMachine::Transition attribute=:state event=:park from="idling" from_name=:idling to="parked" to_name=:parked>]
    #   
    #   # Search for explicit transitions regardless of the current state
    #   events.transitions_for(vehicle, :from => :parked) # => [#<StateMachine::Transition attribute=:state event=:ignite from="parked" from_name=:parked to="idling" to_name=:idling>]
    def transitions_for(object, requirements = {})
      match(requirements).map {|event| event.transition_for(object, requirements)}.compact
    end
    
    # Gets the transition that should be performed for the event stored in the
    # given object's event attribute.  This also takes an additional parameter
    # for automatically invalidating the object if the event or transition are
    # invalid.  By default, this is turned off.
    # 
    # *Note* that if a transition has already been generated for the event, then
    # that transition will be used.
    # 
    # == Examples
    # 
    #   class Vehicle < ActiveRecord::Base
    #     state_machine :initial => :parked do
    #       event :ignite do
    #         transition :parked => :idling
    #       end
    #     end
    #   end
    #   
    #   vehicle = Vehicle.new                       # => #<Vehicle id: nil, state: "parked">
    #   events = Vehicle.state_machine.events
    #   
    #   vehicle.state_event = nil
    #   events.attribute_transition_for(vehicle)    # => nil # Event isn't defined
    #   
    #   vehicle.state_event = 'invalid'
    #   events.attribute_transition_for(vehicle)    # => false # Event is invalid
    #   
    #   vehicle.state_event = 'ignite'
    #   events.attribute_transition_for(vehicle)    # => #<StateMachine::Transition attribute=:state event=:ignite from="parked" from_name=:parked to="idling" to_name=:idling>
    def attribute_transition_for(object, invalidate = false)
      return unless machine.action
      
      result = machine.read(object, :event_transition) || if event_name = machine.read(object, :event)
        if event = self[event_name.to_sym, :name]
          event.transition_for(object) || begin
            # No valid transition: invalidate
            machine.invalidate(object, :event, :invalid_event, [[:state, machine.states.match!(object).human_name(object.class)]]) if invalidate
            false
          end
        else
          # Event is unknown: invalidate
          machine.invalidate(object, :event, :invalid) if invalidate
          false
        end
      end
      
      result
    end
    
    private
      def match(requirements) #:nodoc:
        requirements && requirements[:on] ? [fetch(requirements.delete(:on))] : self
      end
  end
end
