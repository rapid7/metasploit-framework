require 'state_machine/assertions'
require 'state_machine/eval_helpers'

module StateMachine
  # Represents a module which will get evaluated within the context of a state.
  # 
  # Class-level methods are proxied to the owner class, injecting a custom
  # <tt>:if</tt> condition along with method.  This assumes that the method has
  # support for a set of configuration options, including <tt>:if</tt>.  This
  # condition will check that the object's state matches this context's state.
  # 
  # Instance-level methods are used to define state-driven behavior on the
  # state's owner class.
  # 
  # == Examples
  # 
  #   class Vehicle
  #     class << self
  #       attr_accessor :validations
  #       
  #       def validate(options, &block)
  #         validations << options
  #       end
  #     end
  #     
  #     self.validations = []
  #     attr_accessor :state, :simulate
  #     
  #     def moving?
  #       self.class.validations.all? {|validation| validation[:if].call(self)}
  #     end
  #   end
  # 
  # In the above class, a simple set of validation behaviors have been defined.
  # Each validation consists of a configuration like so:
  # 
  #   Vehicle.validate :unless => :simulate
  #   Vehicle.validate :if => lambda {|vehicle| ...}
  # 
  # In order to scope validations to a particular state context, the class-level
  # +validate+ method can be invoked like so:
  # 
  #   machine = StateMachine::Machine.new(Vehicle)
  #   context = StateMachine::StateContext.new(machine.state(:first_gear))
  #   context.validate(:unless => :simulate)
  #   
  #   vehicle = Vehicle.new     # => #<Vehicle:0xb7ce491c @simulate=nil, @state=nil>
  #   vehicle.moving?           # => false
  #   
  #   vehicle.state = 'first_gear'
  #   vehicle.moving?           # => true
  #   
  #   vehicle.simulate = true
  #   vehicle.moving?           # => false
  class StateContext < Module
    include Assertions
    include EvalHelpers
    
    # The state machine for which this context's state is defined
    attr_reader :machine
    
    # The state that must be present in an object for this context to be active
    attr_reader :state
    
    # Creates a new context for the given state
    def initialize(state)
      @state = state
      @machine = state.machine
      
      state_name = state.name
      machine_name = machine.name
      @condition = lambda {|object| object.class.state_machine(machine_name).states.matches?(object, state_name)}
    end
    
    # Creates a new transition that determines what to change the current state
    # to when an event fires from this state.
    # 
    # Since this transition is being defined within a state context, you do
    # *not* need to specify the <tt>:from</tt> option for the transition.  For
    # example:
    # 
    #   state_machine do
    #     state :parked do
    #       transition :to => :idling, :on => [:ignite, :shift_up]                          # Transitions to :idling
    #       transition :from => [:idling, :parked], :on => :park, :unless => :seatbelt_on?  # Transitions to :parked if seatbelt is off
    #     end
    #   end
    # 
    # See StateMachine::Machine#transition for a description of the possible
    # configurations for defining transitions.
    def transition(options)
      assert_valid_keys(options, :from, :to, :on, :if, :unless)
      raise ArgumentError, 'Must specify :on event' unless options[:on]
      raise ArgumentError, 'Must specify either :to or :from state' unless !options[:to] ^ !options[:from]
      
      machine.transition(options.merge(options[:to] ? {:from => state.name} : {:to => state.name}))
    end
    
    # Hooks in condition-merging to methods that don't exist in this module
    def method_missing(*args, &block)
      # Get the configuration
      if args.last.is_a?(Hash)
        options = args.last
      else
        args << options = {}
      end
      
      # Get any existing condition that may need to be merged
      if_condition = options.delete(:if)
      unless_condition = options.delete(:unless)
      
      # Provide scope access to configuration in case the block is evaluated
      # within the object instance
      proxy = self
      proxy_condition = @condition
      
      # Replace the configuration condition with the one configured for this
      # proxy, merging together any existing conditions
      options[:if] = lambda do |*args|
        # Block may be executed within the context of the actual object, so
        # it'll either be the first argument or the executing context
        object = args.first || self
        
        proxy.evaluate_method(object, proxy_condition) &&
        Array(if_condition).all? {|condition| proxy.evaluate_method(object, condition)} &&
        !Array(unless_condition).any? {|condition| proxy.evaluate_method(object, condition)}
      end
      
      # Evaluate the method on the owner class with the condition proxied
      # through
      machine.owner_class.send(*args, &block)
    end
  end
end
