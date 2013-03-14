require 'state_machine/machine_collection'

module StateMachine
  module ClassMethods
    def self.extended(base) #:nodoc:
      base.class_eval do
        @state_machines = MachineCollection.new
      end
    end
    
    # Gets the current list of state machines defined for this class.  This
    # class-level attribute acts like an inheritable attribute.  The attribute
    # is available to each subclass, each having a copy of its superclass's
    # attribute.
    # 
    # The hash of state machines maps <tt>:attribute</tt> => +machine+, e.g.
    # 
    #   Vehicle.state_machines # => {:state => #<StateMachine::Machine:0xb6f6e4a4 ...>}
    def state_machines
      @state_machines ||= superclass.state_machines.dup
    end
  end
  
  module InstanceMethods
    # Runs one or more events in parallel.  All events will run through the
    # following steps:
    # * Before callbacks
    # * Persist state
    # * Invoke action
    # * After callbacks
    # 
    # For example, if two events (for state machines A and B) are run in
    # parallel, the order in which steps are run is:
    # * A - Before transition callbacks
    # * B - Before transition callbacks
    # * A - Persist new state
    # * B - Persist new state
    # * A - Invoke action
    # * B - Invoke action (only if different than A's action)
    # * A - After transition callbacks
    # * B - After transition callbacks
    # 
    # *Note* that multiple events on the same state machine / attribute cannot
    # be run in parallel.  If this is attempted, an ArgumentError will be
    # raised.
    # 
    # == Halting callbacks
    # 
    # When running multiple events in parallel, special consideration should
    # be taken with regard to how halting within callbacks affects the flow.
    # 
    # For *before* callbacks, any <tt>:halt</tt> error that's thrown will
    # immediately cancel the perform for all transitions.  As a result, it's
    # possible for one event's transition to affect the continuation of
    # another.
    # 
    # On the other hand, any <tt>:halt</tt> error that's thrown within an
    # *after* callback with only affect that event's transition.  Other
    # transitions will continue to run their own callbacks.
    # 
    # == Example
    # 
    #   class Vehicle
    #     state_machine :initial => :parked do
    #       event :ignite do
    #         transition :parked => :idling
    #       end
    #       
    #       event :park do
    #         transition :idling => :parked
    #       end
    #     end
    #     
    #     state_machine :alarm_state, :namespace => 'alarm', :initial => :on do
    #       event :enable do
    #         transition all => :active
    #       end
    #       
    #       event :disable do
    #         transition all => :off
    #       end
    #     end
    #   end
    #   
    #   vehicle = Vehicle.new                         # => #<Vehicle:0xb7c02850 @state="parked", @alarm_state="active">
    #   vehicle.state                                 # => "parked"
    #   vehicle.alarm_state                           # => "active"
    #   
    #   vehicle.fire_events(:ignite, :disable_alarm)  # => true
    #   vehicle.state                                 # => "idling"
    #   vehicle.alarm_state                           # => "off"
    #   
    #   # If any event fails, the entire event chain fails
    #   vehicle.fire_events(:ignite, :enable_alarm)   # => false
    #   vehicle.state                                 # => "idling"
    #   vehicle.alarm_state                           # => "off"
    #   
    #   # Exception raised on invalid event
    #   vehicle.fire_events(:park, :invalid)          # => StateMachine::InvalidEvent: :invalid is an unknown event
    #   vehicle.state                                 # => "idling"
    #   vehicle.alarm_state                           # => "off"
    def fire_events(*events)
      self.class.state_machines.fire_events(self, *events)
    end
    
    # Run one or more events in parallel.  If any event fails to run, then
    # a StateMachine::InvalidTransition exception will be raised.
    # 
    # See StateMachine::InstanceMethods#fire_events for more information.
    # 
    # == Example
    # 
    #   class Vehicle
    #     state_machine :initial => :parked do
    #       event :ignite do
    #         transition :parked => :idling
    #       end
    #       
    #       event :park do
    #         transition :idling => :parked
    #       end
    #     end
    #     
    #     state_machine :alarm_state, :namespace => 'alarm', :initial => :active do
    #       event :enable do
    #         transition all => :active
    #       end
    #       
    #       event :disable do
    #         transition all => :off
    #       end
    #     end
    #   end
    #   
    #   vehicle = Vehicle.new                         # => #<Vehicle:0xb7c02850 @state="parked", @alarm_state="active">
    #   vehicle.fire_events(:ignite, :disable_alarm)  # => true
    #   
    #   vehicle.fire_events!(:ignite, :disable_alarm) # => StateMachine::InvalidTranstion: Cannot run events in parallel: ignite, disable_alarm
    def fire_events!(*events)
      run_action = [true, false].include?(events.last) ? events.pop : true
      fire_events(*(events + [run_action])) || raise(StateMachine::InvalidParallelTransition.new(self, events))
    end
    
    protected
      def initialize_state_machines(options = {}, &block) #:nodoc:
        self.class.state_machines.initialize_states(self, options, &block)
      end
  end
end
