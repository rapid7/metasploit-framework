require 'state_machine/extensions'
require 'state_machine/assertions'
require 'state_machine/integrations'

require 'state_machine/helper_module'
require 'state_machine/state'
require 'state_machine/event'
require 'state_machine/callback'
require 'state_machine/node_collection'
require 'state_machine/state_collection'
require 'state_machine/event_collection'
require 'state_machine/path_collection'
require 'state_machine/matcher_helpers'

module StateMachine
  # Represents a state machine for a particular attribute.  State machines
  # consist of states, events and a set of transitions that define how the
  # state changes after a particular event is fired.
  # 
  # A state machine will not know all of the possible states for an object
  # unless they are referenced *somewhere* in the state machine definition.
  # As a result, any unused states should be defined with the +other_states+
  # or +state+ helper.
  # 
  # == Actions
  # 
  # When an action is configured for a state machine, it is invoked when an
  # object transitions via an event.  The success of the event becomes
  # dependent on the success of the action.  If the action is successful, then
  # the transitioned state remains persisted.  However, if the action fails
  # (by returning false), the transitioned state will be rolled back.
  # 
  # For example,
  # 
  #   class Vehicle
  #     attr_accessor :fail, :saving_state
  #     
  #     state_machine :initial => :parked, :action => :save do
  #       event :ignite do
  #         transition :parked => :idling
  #       end
  #       
  #       event :park do
  #         transition :idling => :parked
  #       end
  #     end
  #     
  #     def save
  #       @saving_state = state
  #       fail != true
  #     end
  #   end
  #   
  #   vehicle = Vehicle.new     # => #<Vehicle:0xb7c27024 @state="parked">
  #   vehicle.save              # => true
  #   vehicle.saving_state      # => "parked" # The state was "parked" was save was called
  #   
  #   # Successful event
  #   vehicle.ignite            # => true
  #   vehicle.saving_state      # => "idling" # The state was "idling" when save was called
  #   vehicle.state             # => "idling"
  #   
  #   # Failed event
  #   vehicle.fail = true
  #   vehicle.park              # => false
  #   vehicle.saving_state      # => "parked"
  #   vehicle.state             # => "idling"
  # 
  # As shown, even though the state is set prior to calling the +save+ action
  # on the object, it will be rolled back to the original state if the action
  # fails.  *Note* that this will also be the case if an exception is raised
  # while calling the action.
  # 
  # === Indirect transitions
  # 
  # In addition to the action being run as the _result_ of an event, the action
  # can also be used to run events itself.  For example, using the above as an
  # example:
  # 
  #   vehicle = Vehicle.new           # => #<Vehicle:0xb7c27024 @state="parked">
  #   
  #   vehicle.state_event = 'ignite'
  #   vehicle.save                    # => true
  #   vehicle.state                   # => "idling"
  #   vehicle.state_event             # => nil
  # 
  # As can be seen, the +save+ action automatically invokes the event stored in
  # the +state_event+ attribute (<tt>:ignite</tt> in this case).
  # 
  # One important note about using this technique for running transitions is
  # that if the class in which the state machine is defined *also* defines the
  # action being invoked (and not a superclass), then it must manually run the
  # StateMachine hook that checks for event attributes.
  # 
  # For example, in ActiveRecord, DataMapper, Mongoid, MongoMapper, and Sequel,
  # the default action (+save+) is already defined in a base class.  As a result,
  # when a state machine is defined in a model / resource, StateMachine can
  # automatically hook into the +save+ action.
  # 
  # On the other hand, the Vehicle class from above defined its own +save+
  # method (and there is no +save+ method in its superclass).  As a result, it
  # must be modified like so:
  # 
  #     def save
  #       self.class.state_machines.transitions(self, :save).perform do
  #         @saving_state = state
  #         fail != true
  #       end
  #     end
  # 
  # This will add in the functionality for firing the event stored in the
  # +state_event+ attribute.
  # 
  # == Callbacks
  # 
  # Callbacks are supported for hooking before and after every possible
  # transition in the machine.  Each callback is invoked in the order in which
  # it was defined.  See StateMachine::Machine#before_transition and
  # StateMachine::Machine#after_transition for documentation on how to define
  # new callbacks.
  # 
  # *Note* that callbacks only get executed within the context of an event.  As
  # a result, if a class has an initial state when it's created, any callbacks
  # that would normally get executed when the object enters that state will
  # *not* get triggered.
  # 
  # For example,
  # 
  #   class Vehicle
  #     state_machine :initial => :parked do
  #       after_transition all => :parked do
  #         raise ArgumentError
  #       end
  #       ...
  #     end
  #   end
  #   
  #   vehicle = Vehicle.new   # => #<Vehicle id: 1, state: "parked">
  #   vehicle.save            # => true (no exception raised)
  # 
  # If you need callbacks to get triggered when an object is created, this
  # should be done by one of the following techniques:
  # * Use a <tt>before :create</tt> or equivalent hook:
  # 
  #     class Vehicle
  #       before :create, :track_initial_transition
  #       
  #       state_machine do
  #         ...
  #       end
  #     end
  # 
  # * Set an initial state and use the correct event to create the
  #   object with the proper state, resulting in callbacks being triggered and
  #   the object getting persisted (note that the <tt>:pending</tt> state is
  #   actually stored as nil):
  # 
  #     class Vehicle
  #        state_machine :initial => :pending
  #         after_transition :pending => :parked, :do => :track_initial_transition
  #         
  #         event :park do
  #           transition :pending => :parked
  #         end
  #         
  #         state :pending, :value => nil
  #       end
  #     end
  #     
  #     vehicle = Vehicle.new
  #     vehicle.park
  # 
  # * Use a default event attribute that will automatically trigger when the
  #   configured action gets run (note that the <tt>:pending</tt> state is
  #   actually stored as nil):
  # 
  #     class Vehicle < ActiveRecord::Base
  #       state_machine :initial => :pending
  #         after_transition :pending => :parked, :do => :track_initial_transition
  #         
  #         event :park do
  #           transition :pending => :parked
  #         end
  #         
  #         state :pending, :value => nil
  #       end
  #       
  #       def initialize(*)
  #         super
  #         self.state_event = 'park'
  #       end
  #     end
  #     
  #     vehicle = Vehicle.new
  #     vehicle.save
  # 
  # === Canceling callbacks
  # 
  # Callbacks can be canceled by throwing :halt at any point during the
  # callback.  For example,
  # 
  #   ...
  #   throw :halt
  #   ...
  # 
  # If a +before+ callback halts the chain, the associated transition and all
  # later callbacks are canceled.  If an +after+ callback halts the chain,
  # the later callbacks are canceled, but the transition is still successful.
  # 
  # These same rules apply to +around+ callbacks with the exception that any
  # +around+ callback that doesn't yield will essentially result in :halt being
  # thrown.  Any code executed after the yield will behave in the same way as
  # +after+ callbacks.
  # 
  # *Note* that if a +before+ callback fails and the bang version of an event
  # was invoked, an exception will be raised instead of returning false.  For
  # example,
  # 
  #   class Vehicle
  #     state_machine :initial => :parked do
  #       before_transition any => :idling, :do => lambda {|vehicle| throw :halt}
  #       ...
  #     end
  #   end
  #   
  #   vehicle = Vehicle.new
  #   vehicle.park        # => false
  #   vehicle.park!       # => StateMachine::InvalidTransition: Cannot transition state via :park from "idling"
  # 
  # == Observers
  # 
  # Observers, in the sense of external classes and *not* Ruby's Observable
  # mechanism, can hook into state machines as well.  Such observers use the
  # same callback api that's used internally.
  # 
  # Below are examples of defining observers for the following state machine:
  # 
  #   class Vehicle
  #     state_machine do
  #       event :park do
  #         transition :idling => :parked
  #       end
  #       ...
  #     end
  #     ...
  #   end
  # 
  # Event/Transition behaviors:
  # 
  #   class VehicleObserver
  #     def self.before_park(vehicle, transition)
  #       logger.info "#{vehicle} instructed to park... state is: #{transition.from}, state will be: #{transition.to}"
  #     end
  #     
  #     def self.after_park(vehicle, transition, result)
  #       logger.info "#{vehicle} instructed to park... state was: #{transition.from}, state is: #{transition.to}"
  #     end
  #     
  #     def self.before_transition(vehicle, transition)
  #       logger.info "#{vehicle} instructed to #{transition.event}... #{transition.attribute} is: #{transition.from}, #{transition.attribute} will be: #{transition.to}"
  #     end
  #     
  #     def self.after_transition(vehicle, transition)
  #       logger.info "#{vehicle} instructed to #{transition.event}... #{transition.attribute} was: #{transition.from}, #{transition.attribute} is: #{transition.to}"
  #     end
  #     
  #     def self.around_transition(vehicle, transition)
  #       logger.info Benchmark.measure { yield }
  #     end
  #   end
  #   
  #   Vehicle.state_machine do
  #     before_transition :on => :park, :do => VehicleObserver.method(:before_park)
  #     before_transition VehicleObserver.method(:before_transition)
  #     
  #     after_transition :on => :park, :do => VehicleObserver.method(:after_park)
  #     after_transition VehicleObserver.method(:after_transition)
  #     
  #     around_transition VehicleObserver.method(:around_transition)
  #   end
  # 
  # One common callback is to record transitions for all models in the system
  # for auditing/debugging purposes.  Below is an example of an observer that
  # can easily automate this process for all models:
  # 
  #   class StateMachineObserver
  #     def self.before_transition(object, transition)
  #       Audit.log_transition(object.attributes)
  #     end
  #   end
  #   
  #   [Vehicle, Switch, Project].each do |klass|
  #     klass.state_machines.each do |attribute, machine|
  #       machine.before_transition StateMachineObserver.method(:before_transition)
  #     end
  #   end
  # 
  # Additional observer-like behavior may be exposed by the various integrations
  # available.  See below for more information on integrations.
  # 
  # == Overriding instance / class methods
  # 
  # Hooking in behavior to the generated instance / class methods from the
  # state machine, events, and states is very simple because of the way these
  # methods are generated on the class.  Using the class's ancestors, the
  # original generated method can be referred to via +super+.  For example,
  # 
  #   class Vehicle
  #     state_machine do
  #       event :park do
  #         ...
  #       end
  #     end
  #     
  #     def park(*args)
  #       logger.info "..."
  #       super
  #     end
  #   end
  # 
  # In the above example, the +park+ instance method that's generated on the
  # Vehicle class (by the associated event) is overridden with custom behavior.
  # Once this behavior is complete, the original method from the state machine
  # is invoked by simply calling +super+.
  # 
  # The same technique can be used for +state+, +state_name+, and all other
  # instance *and* class methods on the Vehicle class.
  #
  # == Method conflicts
  # 
  # By default state_machine does not redefine methods that exist on
  # superclasses (*including* Object) or any modules (*including* Kernel) that
  # were included before it was defined.  This is in order to ensure that
  # existing behavior on the class is not broken by the inclusion of
  # state_machine.
  # 
  # If a conflicting method is detected, state_machine will generate a warning.
  # For example, consider the following class:
  # 
  #   class Vehicle
  #     state_machine do
  #       event :open do
  #         ...
  #       end
  #     end
  #   end
  # 
  # In the above class, an event named "open" is defined for its state machine.
  # However, "open" is already defined as an instance method in Ruby's Kernel
  # module that gets included in every Object.  As a result, state_machine will
  # generate the following warning:
  # 
  #   Instance method "open" is already defined in Object, use generic helper instead or set StateMachine::Machine.ignore_method_conflicts = true.
  # 
  # Even though you may not be using Kernel's implementation of the "open"
  # instance method, state_machine isn't aware of this and, as a result, stays
  # safe and just skips redefining the method.
  # 
  # As with almost all helpers methods defined by state_machine in your class,
  # there are generic methods available for working around this method conflict.
  # In the example above, you can invoke the "open" event like so:
  # 
  #   vehicle = Vehicle.new       # => #<Vehicle:0xb72686b4 @state=nil>
  #   vehicle.fire_events(:open)  # => true
  #   
  #   # This will not work
  #   vehicle.open                # => NoMethodError: private method `open' called for #<Vehicle:0xb72686b4 @state=nil>
  # 
  # If you want to take on the risk of overriding existing methods and just
  # ignore method conflicts altogether, you can do so by setting the following
  # configuration:
  # 
  #   StateMachine::Machine.ignore_method_conflicts = true
  # 
  # This will allow you to define events like "open" as described above and
  # still generate the "open" instance helper method.  For example:
  # 
  #   StateMachine::Machine.ignore_method_conflicts = true
  #   
  #   class Vehicle
  #     state_machine do
  #       event :open do
  #         ...
  #     end
  #   end
  #   
  #   vehicle = Vehicle.new   # => #<Vehicle:0xb72686b4 @state=nil>
  #   vehicle.open            # => true
  # 
  # By default, state_machine helps prevent you from making mistakes and
  # accidentally overriding methods that you didn't intend to.  Once you
  # understand this and what the consequences are, setting the
  # +ignore_method_conflicts+ option is a perfectly reasonable workaround.
  # 
  # == Integrations
  # 
  # By default, state machines are library-agnostic, meaning that they work
  # on any Ruby class and have no external dependencies.  However, there are
  # certain libraries which expose additional behavior that can be taken
  # advantage of by state machines.
  # 
  # This library is built to work out of the box with a few popular Ruby
  # libraries that allow for additional behavior to provide a cleaner and
  # smoother experience.  This is especially the case for objects backed by a
  # database that may allow for transactions, persistent storage,
  # search/filters, callbacks, etc.
  # 
  # When a state machine is defined for classes using any of the above libraries,
  # it will try to automatically determine the integration to use (Agnostic,
  # ActiveModel, ActiveRecord, DataMapper, Mongoid, MongoMapper, or Sequel)
  # based on the class definition.  To see how each integration affects the
  # machine's behavior, refer to all constants defined under the
  # StateMachine::Integrations namespace.
  class Machine
    include Assertions
    include EvalHelpers
    include MatcherHelpers
    
    class << self
      # Attempts to find or create a state machine for the given class.  For
      # example,
      # 
      #   StateMachine::Machine.find_or_create(Vehicle)
      #   StateMachine::Machine.find_or_create(Vehicle, :initial => :parked)
      #   StateMachine::Machine.find_or_create(Vehicle, :status)
      #   StateMachine::Machine.find_or_create(Vehicle, :status, :initial => :parked)
      # 
      # If a machine of the given name already exists in one of the class's
      # superclasses, then a copy of that machine will be created and stored
      # in the new owner class (the original will remain unchanged).
      def find_or_create(owner_class, *args, &block)
        options = args.last.is_a?(Hash) ? args.pop : {}
        name = args.first || :state
        
        # Find an existing machine
        if owner_class.respond_to?(:state_machines) && machine = owner_class.state_machines[name]
          # Only create a new copy if changes are being made to the machine in
          # a subclass
          if machine.owner_class != owner_class && (options.any? || block_given?)
            machine = machine.clone
            machine.initial_state = options[:initial] if options.include?(:initial)
            machine.owner_class = owner_class
          end
          
          # Evaluate DSL
          machine.instance_eval(&block) if block_given?
        else
          # No existing machine: create a new one
          machine = new(owner_class, name, options, &block)
        end
        
        machine
      end
      
      # Draws the state machines defined in the given classes using GraphViz.
      # The given classes must be a comma-delimited string of class names.
      # 
      # Configuration options:
      # * <tt>:file</tt> - A comma-delimited string of files to load that
      #   contain the state machine definitions to draw
      # * <tt>:path</tt> - The path to write the graph file to
      # * <tt>:format</tt> - The image format to generate the graph in
      # * <tt>:font</tt> - The name of the font to draw state names in
      def draw(class_names, options = {})
        raise ArgumentError, 'At least one class must be specified' unless class_names && class_names.split(',').any?
        
        # Load any files
        if files = options.delete(:file)
          files.split(',').each {|file| require file}
        end
        
        class_names.split(',').each do |class_name|
          # Navigate through the namespace structure to get to the class
          klass = Object
          class_name.split('::').each do |name|
            klass = klass.const_defined?(name) ? klass.const_get(name) : klass.const_missing(name)
          end
          
          # Draw each of the class's state machines
          klass.state_machines.each_value do |machine|
            machine.draw(options)
          end
        end
      end
    end
    
    # Default messages to use for validation errors in ORM integrations
    class << self; attr_accessor :default_messages; end
    @default_messages = {
      :invalid => 'is invalid',
      :invalid_event => 'cannot transition when %s',
      :invalid_transition => 'cannot transition via "%s"'
    }
    
    # Whether to ignore any conflicts that are detected for helper methods that
    # get generated for a machine's owner class.  Default is false.
    class << self; attr_accessor :ignore_method_conflicts; end
    @ignore_method_conflicts = false
    
    # The class that the machine is defined in
    attr_accessor :owner_class
    
    # The name of the machine, used for scoping methods generated for the
    # machine as a whole (not states or events)
    attr_reader :name
    
    # The events that trigger transitions.  These are sorted, by default, in
    # the order in which they were defined.
    attr_reader :events
    
    # A list of all of the states known to this state machine.  This will pull
    # states from the following sources:
    # * Initial state
    # * State behaviors
    # * Event transitions (:to, :from, and :except_from options)
    # * Transition callbacks (:to, :from, :except_to, and :except_from options)
    # * Unreferenced states (using +other_states+ helper)
    # 
    # These are sorted, by default, in the order in which they were referenced.
    attr_reader :states
    
    # The callbacks to invoke before/after a transition is performed
    # 
    # Maps :before => callbacks and :after => callbacks
    attr_reader :callbacks
    
    # The action to invoke when an object transitions
    attr_reader :action
    
    # An identifier that forces all methods (including state predicates and
    # event methods) to be generated with the value prefixed or suffixed,
    # depending on the context.
    attr_reader :namespace
    
    # Whether the machine will use transactions when firing events
    attr_reader :use_transactions
    
    # Creates a new state machine for the given attribute
    def initialize(owner_class, *args, &block)
      options = args.last.is_a?(Hash) ? args.pop : {}
      assert_valid_keys(options, :attribute, :initial, :initialize, :action, :plural, :namespace, :integration, :messages, :use_transactions)
      
      # Find an integration that matches this machine's owner class
      if options.include?(:integration)
        @integration = StateMachine::Integrations.find_by_name(options[:integration]) if options[:integration]
      else
        @integration = StateMachine::Integrations.match(owner_class)
      end
      
      if @integration
        extend @integration
        options = (@integration.defaults || {}).merge(options)
      end
      
      # Add machine-wide defaults
      options = {:use_transactions => true, :initialize => true}.merge(options)
      
      # Set machine configuration
      @name = args.first || :state
      @attribute = options[:attribute] || @name
      @events = EventCollection.new(self)
      @states = StateCollection.new(self)
      @callbacks = {:before => [], :after => [], :failure => []}
      @namespace = options[:namespace]
      @messages = options[:messages] || {}
      @action = options[:action]
      @use_transactions = options[:use_transactions]
      @initialize_state = options[:initialize]
      self.owner_class = owner_class
      self.initial_state = options[:initial] unless sibling_machines.any?
      
      # Merge with sibling machine configurations
      add_sibling_machine_configs
      
      # Define class integration
      define_helpers
      define_scopes(options[:plural])
      after_initialize
      
      # Evaluate DSL
      instance_eval(&block) if block_given?
    end
    
    # Creates a copy of this machine in addition to copies of each associated
    # event/states/callback, so that the modifications to those collections do
    # not affect the original machine.
    def initialize_copy(orig) #:nodoc:
      super
      
      @events = @events.dup
      @events.machine = self
      @states = @states.dup
      @states.machine = self
      @callbacks = {:before => @callbacks[:before].dup, :after => @callbacks[:after].dup, :failure => @callbacks[:failure].dup}
    end
    
    # Sets the class which is the owner of this state machine.  Any methods
    # generated by states, events, or other parts of the machine will be defined
    # on the given owner class.
    def owner_class=(klass)
      @owner_class = klass
      
      # Create modules for extending the class with state/event-specific methods
      @helper_modules = helper_modules = {:instance => HelperModule.new(self, :instance), :class => HelperModule.new(self, :class)}
      owner_class.class_eval do
        extend helper_modules[:class]
        include helper_modules[:instance]
      end
      
      # Add class-/instance-level methods to the owner class for state initialization
      unless owner_class < StateMachine::InstanceMethods
        owner_class.class_eval do
          extend StateMachine::ClassMethods
          include StateMachine::InstanceMethods
        end
        
        define_state_initializer if @initialize_state
      end
      
      # Record this machine as matched to the name in the current owner class.
      # This will override any machines mapped to the same name in any superclasses.
      owner_class.state_machines[name] = self
    end
    
    # Sets the initial state of the machine.  This can be either the static name
    # of a state or a lambda block which determines the initial state at
    # creation time.
    def initial_state=(new_initial_state)
      @initial_state = new_initial_state
      add_states([@initial_state]) unless dynamic_initial_state?
      
      # Update all states to reflect the new initial state
      states.each {|state| state.initial = (state.name == @initial_state)}
    end
    
    # Gets the initial state of the machine for the given object. If a dynamic
    # initial state was configured for this machine, then the object will be
    # passed into the lambda block to help determine the actual state.
    # 
    # == Examples
    # 
    # With a static initial state:
    # 
    #   class Vehicle
    #     state_machine :initial => :parked do
    #       ...
    #     end
    #   end
    #   
    #   vehicle = Vehicle.new
    #   Vehicle.state_machine.initial_state(vehicle)  # => #<StateMachine::State name=:parked value="parked" initial=true>
    # 
    # With a dynamic initial state:
    # 
    #   class Vehicle
    #     attr_accessor :force_idle
    #     
    #     state_machine :initial => lambda {|vehicle| vehicle.force_idle ? :idling : :parked} do
    #       ...
    #     end
    #   end
    #   
    #   vehicle = Vehicle.new
    #   
    #   vehicle.force_idle = true
    #   Vehicle.state_machine.initial_state(vehicle)  # => #<StateMachine::State name=:idling value="idling" initial=false>
    #   
    #   vehicle.force_idle = false
    #   Vehicle.state_machine.initial_state(vehicle)  # => #<StateMachine::State name=:parked value="parked" initial=false>
    def initial_state(object)
      states.fetch(dynamic_initial_state? ? evaluate_method(object, @initial_state) : @initial_state) if instance_variable_defined?('@initial_state')
    end
    
    # Whether a dynamic initial state is being used in the machine
    def dynamic_initial_state?
      @initial_state.is_a?(Proc)
    end
    
    # Initializes the state on the given object.  Initial values are only set if
    # the machine's attribute hasn't been previously initialized.
    # 
    # Configuration options:
    # * <tt>:force</tt> - Whether to initialize the state regardless of its
    #   current value
    # * <tt>:to</tt> - A hash to set the initial value in instead of writing
    #   directly to the object
    def initialize_state(object, options = {})
      state = initial_state(object)
      if state && (options[:force] || initialize_state?(object))
        value = state.value
        
        if hash = options[:to]
          hash[attribute.to_s] = value
        else
          write(object, :state, value)
        end
      end
    end
    
    # Gets the actual name of the attribute on the machine's owner class that
    # stores data with the given name.
    def attribute(name = :state)
      name == :state ? @attribute : :"#{self.name}_#{name}"
    end
    
    # Defines a new helper method in an instance or class scope with the given
    # name.  If the method is already defined in the scope, then this will not
    # override it.
    # 
    # If passing in a block, there are two side effects to be aware of
    # 1. The method cannot be chained, meaning that the block cannot call +super+
    # 2. If the method is already defined in an ancestor, then it will not get
    #    overridden and a warning will be output.
    # 
    # Example:
    # 
    #   # Instance helper
    #   machine.define_helper(:instance, :state_name) do |machine, object|
    #     machine.states.match(object).name
    #   end
    #   
    #   # Class helper
    #   machine.define_helper(:class, :state_machine_name) do |machine, klass|
    #     "State"
    #   end
    # 
    # You can also define helpers using string evaluation like so:
    # 
    #   # Instance helper
    #   machine.define_helper :instance, <<-end_eval, __FILE__, __LINE__ + 1
    #     def state_name
    #       self.class.state_machine(:state).states.match(self).name
    #     end
    #   end_eval
    #   
    #   # Class helper
    #   machine.define_helper :class, <<-end_eval, __FILE__, __LINE__ + 1
    #     def state_machine_name
    #       "State"
    #     end
    #   end_eval
    def define_helper(scope, method, *args, &block)
      helper_module = @helper_modules.fetch(scope)
      
      if block_given?
        if !self.class.ignore_method_conflicts && conflicting_ancestor = owner_class_ancestor_has_method?(scope, method)
          ancestor_name = conflicting_ancestor.name && !conflicting_ancestor.name.empty? ? conflicting_ancestor.name : conflicting_ancestor.to_s
          warn "#{scope == :class ? 'Class' : 'Instance'} method \"#{method}\" is already defined in #{ancestor_name}, use generic helper instead or set StateMachine::Machine.ignore_method_conflicts = true."
        else
          name = self.name
          helper_module.class_eval do
            define_method(method) do |*args|
              block.call((scope == :instance ? self.class : self).state_machine(name), self, *args)
            end
          end
        end
      else
        helper_module.class_eval(method, *args)
      end
    end
    
    # Customizes the definition of one or more states in the machine.
    # 
    # Configuration options:
    # * <tt>:value</tt> - The actual value to store when an object transitions
    #   to the state.  Default is the name (stringified).
    # * <tt>:cache</tt> - If a dynamic value (via a lambda block) is being used,
    #   then setting this to true will cache the evaluated result
    # * <tt>:if</tt> - Determines whether an object's value matches the state
    #   (e.g. :value => lambda {Time.now}, :if => lambda {|state| !state.nil?}).
    #   By default, the configured value is matched.
    # * <tt>:human_name</tt> - The human-readable version of this state's name.
    #   By default, this is either defined by the integration or stringifies the
    #   name and converts underscores to spaces.
    # 
    # == Customizing the stored value
    # 
    # Whenever a state is automatically discovered in the state machine, its
    # default value is assumed to be the stringified version of the name.  For
    # example,
    # 
    #   class Vehicle
    #     state_machine :initial => :parked do
    #       event :ignite do
    #         transition :parked => :idling
    #       end
    #     end
    #   end
    # 
    # In the above state machine, there are two states automatically discovered:
    # :parked and :idling.  These states, by default, will store their stringified
    # equivalents when an object moves into that state (e.g. "parked" / "idling").
    # 
    # For legacy systems or when tying state machines into existing frameworks,
    # it's oftentimes necessary to need to store a different value for a state
    # than the default.  In order to continue taking advantage of an expressive
    # state machine and helper methods, every defined state can be re-configured
    # with a custom stored value.  For example,
    # 
    #   class Vehicle
    #     state_machine :initial => :parked do
    #       event :ignite do
    #         transition :parked => :idling
    #       end
    #       
    #       state :idling, :value => 'IDLING'
    #       state :parked, :value => 'PARKED
    #     end
    #   end
    # 
    # This is also useful if being used in association with a database and,
    # instead of storing the state name in a column, you want to store the
    # state's foreign key:
    # 
    #   class VehicleState < ActiveRecord::Base
    #   end
    #   
    #   class Vehicle < ActiveRecord::Base
    #     state_machine :attribute => :state_id, :initial => :parked do
    #       event :ignite do
    #         transition :parked => :idling
    #       end
    #       
    #       states.each do |state|
    #         self.state(state.name, :value => lambda { VehicleState.find_by_name(state.name.to_s).id }, :cache => true)
    #       end
    #     end
    #   end
    # 
    # In the above example, each known state is configured to store it's
    # associated database id in the +state_id+ attribute.  Also, notice that a
    # lambda block is used to define the state's value.  This is required in
    # situations (like testing) where the model is loaded without any existing
    # data (i.e. no VehicleState records available).
    # 
    # One caveat to the above example is to keep performance in mind.  To avoid
    # constant db hits for looking up the VehicleState ids, the value is cached
    # by specifying the <tt>:cache</tt> option.  Alternatively, a custom
    # caching strategy can be used like so:
    # 
    #   class VehicleState < ActiveRecord::Base
    #     cattr_accessor :cache_store
    #     self.cache_store = ActiveSupport::Cache::MemoryStore.new
    #     
    #     def self.find_by_name(name)
    #       cache_store.fetch(name) { find(:first, :conditions => {:name => name}) }
    #     end
    #   end
    # 
    # === Dynamic values
    # 
    # In addition to customizing states with other value types, lambda blocks
    # can also be specified to allow for a state's value to be determined
    # dynamically at runtime.  For example,
    # 
    #   class Vehicle
    #     state_machine :purchased_at, :initial => :available do
    #       event :purchase do
    #         transition all => :purchased
    #       end
    #       
    #       event :restock do
    #         transition all => :available
    #       end
    #       
    #       state :available, :value => nil
    #       state :purchased, :if => lambda {|value| !value.nil?}, :value => lambda {Time.now}
    #     end
    #   end
    # 
    # In the above definition, the <tt>:purchased</tt> state is customized with
    # both a dynamic value *and* a value matcher.
    # 
    # When an object transitions to the purchased state, the value's lambda
    # block will be called.  This will get the current time and store it in the
    # object's +purchased_at+ attribute.
    # 
    # *Note* that the custom matcher is very important here.  Since there's no
    # way for the state machine to figure out an object's state when it's set to
    # a runtime value, it must be explicitly defined.  If the <tt>:if</tt> option
    # were not configured for the state, then an ArgumentError exception would
    # be raised at runtime, indicating that the state machine could not figure
    # out what the current state of the object was.
    # 
    # == Behaviors
    # 
    # Behaviors define a series of methods to mixin with objects when the current
    # state matches the given one(s).  This allows instance methods to behave
    # a specific way depending on what the value of the object's state is.
    # 
    # For example,
    # 
    #   class Vehicle
    #     attr_accessor :driver
    #     attr_accessor :passenger
    #     
    #     state_machine :initial => :parked do
    #       event :ignite do
    #         transition :parked => :idling
    #       end
    #       
    #       state :parked do
    #         def speed
    #           0
    #         end
    #         
    #         def rotate_driver
    #           driver = self.driver
    #           self.driver = passenger
    #           self.passenger = driver
    #           true
    #         end
    #       end
    #       
    #       state :idling, :first_gear do
    #         def speed
    #           20
    #         end
    #         
    #         def rotate_driver
    #           self.state = 'parked'
    #           rotate_driver
    #         end
    #       end
    #       
    #       other_states :backing_up
    #     end
    #   end
    # 
    # In the above example, there are two dynamic behaviors defined for the
    # class:
    # * +speed+
    # * +rotate_driver+
    # 
    # Each of these behaviors are instance methods on the Vehicle class.  However,
    # which method actually gets invoked is based on the current state of the
    # object.  Using the above class as the example:
    # 
    #   vehicle = Vehicle.new
    #   vehicle.driver = 'John'
    #   vehicle.passenger = 'Jane'
    #   
    #   # Behaviors in the "parked" state
    #   vehicle.state             # => "parked"
    #   vehicle.speed             # => 0
    #   vehicle.rotate_driver     # => true
    #   vehicle.driver            # => "Jane"
    #   vehicle.passenger         # => "John"
    #   
    #   vehicle.ignite            # => true
    #   
    #   # Behaviors in the "idling" state
    #   vehicle.state             # => "idling"
    #   vehicle.speed             # => 20
    #   vehicle.rotate_driver     # => true
    #   vehicle.driver            # => "John"
    #   vehicle.passenger         # => "Jane"
    # 
    # As can be seen, both the +speed+ and +rotate_driver+ instance method
    # implementations changed how they behave based on what the current state
    # of the vehicle was.
    # 
    # === Invalid behaviors
    # 
    # If a specific behavior has not been defined for a state, then a
    # NoMethodError exception will be raised, indicating that that method would
    # not normally exist for an object with that state.
    # 
    # Using the example from before:
    # 
    #   vehicle = Vehicle.new
    #   vehicle.state = 'backing_up'
    #   vehicle.speed               # => NoMethodError: undefined method 'speed' for #<Vehicle:0xb7d296ac> in state "backing_up"
    # 
    # === Using matchers
    # 
    # The +all+ / +any+ matchers can be used to easily define behaviors for a
    # group of states.  Note, however, that you cannot use these matchers to
    # set configurations for states.  Behaviors using these matchers can be
    # defined at any point in the state machine and will always get applied to
    # the proper states.
    # 
    # For example:
    # 
    #   state_machine :initial => :parked do
    #     ...
    #     
    #     state all - [:parked, :idling, :stalled] do
    #       validates_presence_of :speed
    #       
    #       def speed
    #         gear * 10
    #       end
    #     end
    #   end
    # 
    # == State-aware class methods
    # 
    # In addition to defining scopes for instance methods that are state-aware,
    # the same can be done for certain types of class methods.
    # 
    # Some libraries have support for class-level methods that only run certain
    # behaviors based on a conditions hash passed in.  For example:
    # 
    #   class Vehicle < ActiveRecord::Base
    #     state_machine do
    #       ...
    #       state :first_gear, :second_gear, :third_gear do
    #         validates_presence_of   :speed
    #         validates_inclusion_of  :speed, :in => 0..25, :if => :in_school_zone?
    #       end
    #     end
    #   end
    # 
    # In the above ActiveRecord model, two validations have been defined which
    # will *only* run when the Vehicle object is in one of the three states:
    # +first_gear+, +second_gear+, or +third_gear.  Notice, also, that if/unless
    # conditions can continue to be used.
    # 
    # This functionality is not library-specific and can work for any class-level
    # method that is defined like so:
    # 
    #   def validates_presence_of(attribute, options = {})
    #     ...
    #   end
    # 
    # The minimum requirement is that the last argument in the method be an
    # options hash which contains at least <tt>:if</tt> condition support.
    def state(*names, &block)
      options = names.last.is_a?(Hash) ? names.pop : {}
      assert_valid_keys(options, :value, :cache, :if, :human_name)
      
      # Store the context so that it can be used for / matched against any state
      # that gets added
      @states.context(names, &block) if block_given?
      
      if names.first.is_a?(Matcher)
        # Add any states referenced in the matcher.  When matchers are used,
        # states are not allowed to be configured.
        raise ArgumentError, "Cannot configure states when using matchers (using #{options.inspect})" if options.any?
        states = add_states(names.first.values)
      else
        states = add_states(names)
        
        # Update the configuration for the state(s)
        states.each do |state|
          if options.include?(:value)
            state.value = options[:value]
            self.states.update(state)
          end
          
          state.human_name = options[:human_name] if options.include?(:human_name)
          state.cache = options[:cache] if options.include?(:cache)
          state.matcher = options[:if] if options.include?(:if)
        end
      end
      
      states.length == 1 ? states.first : states
    end
    alias_method :other_states, :state
    
    # Gets the current value stored in the given object's attribute.
    # 
    # For example,
    # 
    #   class Vehicle
    #     state_machine :initial => :parked do
    #       ...
    #     end
    #   end
    #   
    #   vehicle = Vehicle.new                           # => #<Vehicle:0xb7d94ab0 @state="parked">
    #   Vehicle.state_machine.read(vehicle, :state)     # => "parked" # Equivalent to vehicle.state
    #   Vehicle.state_machine.read(vehicle, :event)     # => nil      # Equivalent to vehicle.state_event
    def read(object, attribute, ivar = false)
      attribute = self.attribute(attribute)
      ivar ? object.instance_variable_get("@#{attribute}") : object.send(attribute)
    end
    
    # Sets a new value in the given object's attribute.
    # 
    # For example,
    # 
    #   class Vehicle
    #     state_machine :initial => :parked do
    #       ...
    #     end
    #   end
    #   
    #   vehicle = Vehicle.new                                   # => #<Vehicle:0xb7d94ab0 @state="parked">
    #   Vehicle.state_machine.write(vehicle, :state, 'idling')  # => Equivalent to vehicle.state = 'idling'
    #   Vehicle.state_machine.write(vehicle, :event, 'park')    # => Equivalent to vehicle.state_event = 'park'
    #   vehicle.state                                           # => "idling"
    #   vehicle.event                                           # => "park"
    def write(object, attribute, value, ivar = false)
      attribute = self.attribute(attribute)
      ivar ? object.instance_variable_set("@#{attribute}", value) : object.send("#{attribute}=", value)
    end
    
    # Defines one or more events for the machine and the transitions that can
    # be performed when those events are run.
    # 
    # This method is also aliased as +on+ for improved compatibility with
    # using a domain-specific language.
    # 
    # Configuration options:
    # * <tt>:human_name</tt> - The human-readable version of this event's name.
    #   By default, this is either defined by the integration or stringifies the
    #   name and converts underscores to spaces.
    # 
    # == Instance methods
    # 
    # The following instance methods are generated when a new event is defined
    # (the "park" event is used as an example):
    # * <tt>park(..., run_action = true)</tt> - Fires the "park" event,
    #   transitioning from the current state to the next valid state.  If the
    #   last argument is a boolean, it will control whether the machine's action
    #   gets run.
    # * <tt>park!(..., run_action = true)</tt> - Fires the "park" event,
    #   transitioning from the current state to the next valid state.  If the
    #   transition fails, then a StateMachine::InvalidTransition error will be
    #   raised.  If the last argument is a boolean, it will control whether the
    #   machine's action gets run.
    # * <tt>can_park?(requirements = {})</tt> - Checks whether the "park" event
    #   can be fired given the current state of the object.  This will *not* run
    #   validations or callbacks in ORM integrations.  It will only determine if
    #   the state machine defines a valid transition for the event.  To check
    #   whether an event can fire *and* passes validations, use event attributes
    #   (e.g. state_event) as described in the "Events" documentation of each
    #   ORM integration.
    # * <tt>park_transition(requirements = {})</tt> -  Gets the next transition
    #   that would be performed if the "park" event were to be fired now on the
    #   object or nil if no transitions can be performed.  Like <tt>can_park?</tt>
    #   this will also *not* run validations or callbacks.  It will only
    #   determine if the state machine defines a valid transition for the event.
    # 
    # With a namespace of "car", the above names map to the following methods:
    # * <tt>can_park_car?</tt>
    # * <tt>park_car_transition</tt>
    # * <tt>park_car</tt>
    # * <tt>park_car!</tt>
    # 
    # The <tt>can_park?</tt> and <tt>park_transition</tt> helpers both take an
    # optional set of requirements for determining what transitions are available
    # for the current object.  These requirements include:
    # * <tt>:from</tt> - One or more states to transition from.  If none are
    #   specified, then this will be the object's current state.
    # * <tt>:to</tt> - One or more states to transition to.  If none are
    #   specified, then this will match any to state.
    # * <tt>:guard</tt> - Whether to guard transitions with the if/unless
    #   conditionals defined for each one.  Default is true.
    # 
    # == Defining transitions
    # 
    # +event+ requires a block which allows you to define the possible
    # transitions that can happen as a result of that event.  For example,
    # 
    #   event :park, :stop do
    #     transition :idling => :parked
    #   end
    #   
    #   event :first_gear do
    #     transition :parked => :first_gear, :if => :seatbelt_on?
    #     transition :parked => same # Allow to loopback if seatbelt is off
    #   end
    # 
    # See StateMachine::Event#transition for more information on
    # the possible options that can be passed in.
    # 
    # *Note* that this block is executed within the context of the actual event
    # object.  As a result, you will not be able to reference any class methods
    # on the model without referencing the class itself.  For example,
    # 
    #   class Vehicle
    #     def self.safe_states
    #       [:parked, :idling, :stalled]
    #     end
    #     
    #     state_machine do
    #       event :park do
    #         transition Vehicle.safe_states => :parked
    #       end
    #     end
    #   end 
    # 
    # == Overriding the event method
    # 
    # By default, this will define an instance method (with the same name as the
    # event) that will fire the next possible transition for that.  Although the
    # +before_transition+, +after_transition+, and +around_transition+ hooks
    # allow you to define behavior that gets executed as a result of the event's
    # transition, you can also override the event method in order to have a
    # little more fine-grained control.
    # 
    # For example:
    # 
    #   class Vehicle
    #     state_machine do
    #       event :park do
    #         ...
    #       end
    #     end
    #     
    #     def park(*)
    #       take_deep_breath  # Executes before the transition (and before_transition hooks) even if no transition is possible
    #       if result = super # Runs the transition and all before/after/around hooks
    #         applaud         # Executes after the transition (and after_transition hooks)
    #       end
    #       result
    #     end
    #   end
    # 
    # There are a few important things to note here.  First, the method
    # signature is defined with an unlimited argument list in order to allow
    # callers to continue passing arguments that are expected by state_machine.
    # For example, it will still allow calls to +park+ with a single parameter
    # for skipping the configured action.
    # 
    # Second, the overridden event method must call +super+ in order to run the
    # logic for running the next possible transition.  In order to remain
    # consistent with other events, the result of +super+ is returned.
    # 
    # Third, any behavior defined in this method will *not* get executed if
    # you're taking advantage of attribute-based event transitions.  For example:
    # 
    #   vehicle = Vehicle.new
    #   vehicle.state_event = 'park'
    #   vehicle.save
    # 
    # In this case, the +park+ event will run the before/after/around transition
    # hooks and transition the state, but the behavior defined in the overriden
    # +park+ method will *not* be executed.
    # 
    # == Defining additional arguments
    # 
    # Additional arguments can be passed into events and accessed by transition
    # hooks like so:
    # 
    #   class Vehicle
    #     state_machine do
    #       after_transition :on => :park do |vehicle, transition|
    #         kind = *transition.args # :parallel
    #         ...
    #       end
    #       after_transition :on => :park, :do => :take_deep_breath
    #       
    #       event :park do
    #         ...
    #       end
    #       
    #       def take_deep_breath(transition)
    #         kind = *transition.args # :parallel
    #         ...
    #       end
    #     end
    #   end
    #   
    #   vehicle = Vehicle.new
    #   vehicle.park(:parallel)
    # 
    # *Remember* that if the last argument is a boolean, it will be used as the
    # +run_action+ parameter to the event action.  Using the +park+ action
    # example from above, you can might call it like so:
    # 
    #   vehicle.park                    # => Uses default args and runs machine action
    #   vehicle.park(:parallel)         # => Specifies the +kind+ argument and runs the machine action
    #   vehicle.park(:parallel, false)  # => Specifies the +kind+ argument and *skips* the machine action
    # 
    # If you decide to override the +park+ event method *and* define additional
    # arguments, you can do so as shown below:
    # 
    #   class Vehicle
    #     state_machine do
    #       event :park do
    #         ...
    #       end
    #     end
    #     
    #     def park(kind = :parallel, *args)
    #       take_deep_breath if kind == :parallel
    #       super
    #     end
    #   end
    # 
    # Note that +super+ is called instead of <tt>super(*args)</tt>.  This allow
    # the entire arguments list to be accessed by transition callbacks through
    # StateMachine::Transition#args.
    # 
    # === Using matchers
    # 
    # The +all+ / +any+ matchers can be used to easily execute blocks for a
    # group of events.  Note, however, that you cannot use these matchers to
    # set configurations for events.  Blocks using these matchers can be
    # defined at any point in the state machine and will always get applied to
    # the proper events.
    # 
    # For example:
    # 
    #   state_machine :initial => :parked do
    #     ...
    #     
    #     event all - [:crash] do
    #       transition :stalled => :parked
    #     end
    #   end
    # 
    # == Example
    # 
    #   class Vehicle
    #     state_machine do
    #       # The park, stop, and halt events will all share the given transitions
    #       event :park, :stop, :halt do
    #         transition [:idling, :backing_up] => :parked
    #       end
    #       
    #       event :stop do
    #         transition :first_gear => :idling
    #       end
    #       
    #       event :ignite do
    #         transition :parked => :idling
    #         transition :idling => same # Allow ignite while still idling
    #       end
    #     end
    #   end
    def event(*names, &block)
      options = names.last.is_a?(Hash) ? names.pop : {}
      assert_valid_keys(options, :human_name)
      
      # Store the context so that it can be used for / matched against any event
      # that gets added
      @events.context(names, &block) if block_given?
      
      if names.first.is_a?(Matcher)
        # Add any events referenced in the matcher.  When matchers are used,
        # events are not allowed to be configured.
        raise ArgumentError, "Cannot configure events when using matchers (using #{options.inspect})" if options.any?
        events = add_events(names.first.values)
      else
        events = add_events(names)
        
        # Update the configuration for the event(s)
        events.each do |event|
          event.human_name = options[:human_name] if options.include?(:human_name)
          
          # Add any states that may have been referenced within the event
          add_states(event.known_states)
        end
      end
      
      events.length == 1 ? events.first : events
    end
    alias_method :on, :event
    
    # Creates a new transition that determines what to change the current state
    # to when an event fires.
    # 
    # == Defining transitions
    # 
    # The options for a new transition uses the Hash syntax to map beginning
    # states to ending states.  For example,
    # 
    #   transition :parked => :idling, :idling => :first_gear, :on => :ignite
    # 
    # In this case, when the +ignite+ event is fired, this transition will cause
    # the state to be +idling+ if it's current state is +parked+ or +first_gear+
    # if it's current state is +idling+.
    # 
    # To help define these implicit transitions, a set of helpers are available
    # for slightly more complex matching:
    # * <tt>all</tt> - Matches every state in the machine
    # * <tt>all - [:parked, :idling, ...]</tt> - Matches every state except those specified
    # * <tt>any</tt> - An alias for +all+ (matches every state in the machine)
    # * <tt>same</tt> - Matches the same state being transitioned from
    # 
    # See StateMachine::MatcherHelpers for more information.
    # 
    # Examples:
    # 
    #   transition all => nil, :on => :ignite                               # Transitions to nil regardless of the current state
    #   transition all => :idling, :on => :ignite                           # Transitions to :idling regardless of the current state
    #   transition all - [:idling, :first_gear] => :idling, :on => :ignite  # Transitions every state but :idling and :first_gear to :idling
    #   transition nil => :idling, :on => :ignite                           # Transitions to :idling from the nil state
    #   transition :parked => :idling, :on => :ignite                       # Transitions to :idling if :parked
    #   transition [:parked, :stalled] => :idling, :on => :ignite           # Transitions to :idling if :parked or :stalled
    #   
    #   transition :parked => same, :on => :park                            # Loops :parked back to :parked
    #   transition [:parked, :stalled] => same, :on => [:park, :stall]      # Loops either :parked or :stalled back to the same state on the park and stall events
    #   transition all - :parked => same, :on => :noop                      # Loops every state but :parked back to the same state
    #   
    #   # Transitions to :idling if :parked, :first_gear if :idling, or :second_gear if :first_gear
    #   transition :parked => :idling, :idling => :first_gear, :first_gear => :second_gear, :on => :shift_up
    # 
    # == Verbose transitions
    # 
    # Transitions can also be defined use an explicit set of configuration
    # options:
    # * <tt>:from</tt> - A state or array of states that can be transitioned from.
    #   If not specified, then the transition can occur for *any* state.
    # * <tt>:to</tt> - The state that's being transitioned to.  If not specified,
    #   then the transition will simply loop back (i.e. the state will not change).
    # * <tt>:except_from</tt> - A state or array of states that *cannot* be
    #   transitioned from.
    # 
    # These options must be used when defining transitions within the context
    # of a state.
    # 
    # Examples:
    # 
    #   transition :to => nil, :on => :park
    #   transition :to => :idling, :on => :ignite
    #   transition :except_from => [:idling, :first_gear], :to => :idling, :on => :ignite
    #   transition :from => nil, :to => :idling, :on => :ignite
    #   transition :from => [:parked, :stalled], :to => :idling, :on => :ignite
    #   
    # == Conditions
    # 
    # In addition to the state requirements for each transition, a condition
    # can also be defined to help determine whether that transition is
    # available.  These options will work on both the normal and verbose syntax.
    # 
    # Configuration options:
    # * <tt>:if</tt> - A method, proc or string to call to determine if the
    #   transition should occur (e.g. :if => :moving?, or :if => lambda {|vehicle| vehicle.speed > 60}).
    #   The condition should return or evaluate to true or false.
    # * <tt>:unless</tt> - A method, proc or string to call to determine if the
    #   transition should not occur (e.g. :unless => :stopped?, or :unless => lambda {|vehicle| vehicle.speed <= 60}).
    #   The condition should return or evaluate to true or false.
    # 
    # Examples:
    # 
    #   transition :parked => :idling, :on => :ignite, :if => :moving?
    #   transition :parked => :idling, :on => :ignite, :unless => :stopped?
    #   transition :idling => :first_gear, :first_gear => :second_gear, :on => :shift_up, :if => :seatbelt_on?
    #   
    #   transition :from => :parked, :to => :idling, :on => ignite, :if => :moving?
    #   transition :from => :parked, :to => :idling, :on => ignite, :unless => :stopped?
    # 
    # == Order of operations
    # 
    # Transitions are evaluated in the order in which they're defined.  As a
    # result, if more than one transition applies to a given object, then the
    # first transition that matches will be performed.
    def transition(options)
      raise ArgumentError, 'Must specify :on event' unless options[:on]
      
      branches = []
      options = options.dup
      event(*Array(options.delete(:on))) { branches << transition(options) }
      
      branches.length == 1 ? branches.first : branches
    end
    
    # Creates a callback that will be invoked *before* a transition is
    # performed so long as the given requirements match the transition.
    # 
    # == The callback
    # 
    # Callbacks must be defined as either an argument, in the :do option, or
    # as a block.  For example,
    # 
    #   class Vehicle
    #     state_machine do
    #       before_transition :set_alarm
    #       before_transition :set_alarm, all => :parked
    #       before_transition all => :parked, :do => :set_alarm
    #       before_transition all => :parked do |vehicle, transition|
    #         vehicle.set_alarm
    #       end
    #       ...
    #     end
    #   end
    # 
    # Notice that the first three callbacks are the same in terms of how the
    # methods to invoke are defined.  However, using the <tt>:do</tt> can
    # provide for a more fluid DSL.
    # 
    # In addition, multiple callbacks can be defined like so:
    # 
    #   class Vehicle
    #     state_machine do
    #       before_transition :set_alarm, :lock_doors, all => :parked
    #       before_transition all => :parked, :do => [:set_alarm, :lock_doors]
    #       before_transition :set_alarm do |vehicle, transition|
    #         vehicle.lock_doors
    #       end
    #     end
    #   end
    # 
    # Notice that the different ways of configuring methods can be mixed.
    # 
    # == State requirements
    # 
    # Callbacks can require that the machine be transitioning from and to
    # specific states.  These requirements use a Hash syntax to map beginning
    # states to ending states.  For example,
    # 
    #   before_transition :parked => :idling, :idling => :first_gear, :do => :set_alarm
    # 
    # In this case, the +set_alarm+ callback will only be called if the machine
    # is transitioning from +parked+ to +idling+ or from +idling+ to +parked+.
    # 
    # To help define state requirements, a set of helpers are available for
    # slightly more complex matching:
    # * <tt>all</tt> - Matches every state/event in the machine
    # * <tt>all - [:parked, :idling, ...]</tt> - Matches every state/event except those specified
    # * <tt>any</tt> - An alias for +all+ (matches every state/event in the machine)
    # * <tt>same</tt> - Matches the same state being transitioned from
    # 
    # See StateMachine::MatcherHelpers for more information.
    # 
    # Examples:
    # 
    #   before_transition :parked => [:idling, :first_gear], :do => ...     # Matches from parked to idling or first_gear
    #   before_transition all - [:parked, :idling] => :idling, :do => ...   # Matches from every state except parked and idling to idling
    #   before_transition all => :parked, :do => ...                        # Matches all states to parked
    #   before_transition any => same, :do => ...                           # Matches every loopback
    # 
    # == Event requirements
    # 
    # In addition to state requirements, an event requirement can be defined so
    # that the callback is only invoked on specific events using the +on+
    # option.  This can also use the same matcher helpers as the state
    # requirements.
    # 
    # Examples:
    # 
    #   before_transition :on => :ignite, :do => ...                        # Matches only on ignite
    #   before_transition :on => all - :ignite, :do => ...                  # Matches on every event except ignite
    #   before_transition :parked => :idling, :on => :ignite, :do => ...    # Matches from parked to idling on ignite
    # 
    # == Verbose Requirements
    # 
    # Requirements can also be defined using verbose options rather than the
    # implicit Hash syntax and helper methods described above.
    # 
    # Configuration options:
    # * <tt>:from</tt> - One or more states being transitioned from.  If none
    #   are specified, then all states will match.
    # * <tt>:to</tt> - One or more states being transitioned to.  If none are
    #   specified, then all states will match.
    # * <tt>:on</tt> - One or more events that fired the transition.  If none
    #   are specified, then all events will match.
    # * <tt>:except_from</tt> - One or more states *not* being transitioned from
    # * <tt>:except_to</tt> - One more states *not* being transitioned to
    # * <tt>:except_on</tt> - One or more events that *did not* fire the transition
    # 
    # Examples:
    # 
    #   before_transition :from => :ignite, :to => :idling, :on => :park, :do => ...
    #   before_transition :except_from => :ignite, :except_to => :idling, :except_on => :park, :do => ...
    # 
    # == Conditions
    # 
    # In addition to the state/event requirements, a condition can also be
    # defined to help determine whether the callback should be invoked.
    # 
    # Configuration options:
    # * <tt>:if</tt> - A method, proc or string to call to determine if the
    #   callback should occur (e.g. :if => :allow_callbacks, or
    #   :if => lambda {|user| user.signup_step > 2}). The method, proc or string
    #   should return or evaluate to a true or false value. 
    # * <tt>:unless</tt> - A method, proc or string to call to determine if the
    #   callback should not occur (e.g. :unless => :skip_callbacks, or
    #   :unless => lambda {|user| user.signup_step <= 2}). The method, proc or
    #   string should return or evaluate to a true or false value. 
    # 
    # Examples:
    # 
    #   before_transition :parked => :idling, :if => :moving?, :do => ...
    #   before_transition :on => :ignite, :unless => :seatbelt_on?, :do => ...
    # 
    # == Accessing the transition
    # 
    # In addition to passing the object being transitioned, the actual
    # transition describing the context (e.g. event, from, to) can be accessed
    # as well.  This additional argument is only passed if the callback allows
    # for it.
    # 
    # For example,
    # 
    #   class Vehicle
    #     # Only specifies one parameter (the object being transitioned)
    #     before_transition all => :parked do |vehicle|
    #       vehicle.set_alarm
    #     end
    #     
    #     # Specifies 2 parameters (object being transitioned and actual transition)
    #     before_transition all => :parked do |vehicle, transition|
    #       vehicle.set_alarm(transition)
    #     end
    #   end
    # 
    # *Note* that the object in the callback will only be passed in as an
    # argument if callbacks are configured to *not* be bound to the object
    # involved.  This is the default and may change on a per-integration basis.
    # 
    # See StateMachine::Transition for more information about the
    # attributes available on the transition.
    # 
    # == Usage with delegates
    # 
    # As noted above, state_machine uses the callback method's argument list
    # arity to determine whether to include the transition in the method call.
    # If you're using delegates, such as those defined in ActiveSupport or
    # Forwardable, the actual arity of the delegated method gets masked.  This
    # means that callbacks which reference delegates will always get passed the
    # transition as an argument.  For example:
    # 
    #   class Vehicle
    #     extend Forwardable
    #     delegate :refresh => :dashboard
    #     
    #     state_machine do
    #       before_transition :refresh
    #       ...
    #     end
    #     
    #     def dashboard
    #       @dashboard ||= Dashboard.new
    #     end
    #   end
    #   
    #   class Dashboard
    #     def refresh(transition)
    #       # ...
    #     end
    #   end
    # 
    # In the above example, <tt>Dashboard#refresh</tt> *must* defined a
    # +transition+ argument.  Otherwise, an +ArgumentError+ exception will get
    # raised.  The only way around this is to avoid the use of delegates and
    # manually define the delegate method so that the correct arity is used.
    # 
    # == Examples
    # 
    # Below is an example of a class with one state machine and various types
    # of +before+ transitions defined for it:
    # 
    #   class Vehicle
    #     state_machine do
    #       # Before all transitions
    #       before_transition :update_dashboard
    #       
    #       # Before specific transition:
    #       before_transition [:first_gear, :idling] => :parked, :on => :park, :do => :take_off_seatbelt
    #       
    #       # With conditional callback:
    #       before_transition all => :parked, :do => :take_off_seatbelt, :if => :seatbelt_on?
    #       
    #       # Using helpers:
    #       before_transition all - :stalled => same, :on => any - :crash, :do => :update_dashboard
    #       ...
    #     end
    #   end
    # 
    # As can be seen, any number of transitions can be created using various
    # combinations of configuration options.
    def before_transition(*args, &block)
      options = (args.last.is_a?(Hash) ? args.pop : {})
      options[:do] = args if args.any?
      add_callback(:before, options, &block)
    end
    
    # Creates a callback that will be invoked *after* a transition is
    # performed so long as the given requirements match the transition.
    # 
    # See +before_transition+ for a description of the possible configurations
    # for defining callbacks.
    def after_transition(*args, &block)
      options = (args.last.is_a?(Hash) ? args.pop : {})
      options[:do] = args if args.any?
      add_callback(:after, options, &block)
    end
    
    # Creates a callback that will be invoked *around* a transition so long as
    # the given requirements match the transition.
    # 
    # == The callback
    # 
    # Around callbacks wrap transitions, executing code both before and after.
    # These callbacks are defined in the exact same manner as before / after
    # callbacks with the exception that the transition must be yielded to in
    # order to finish running it.
    # 
    # If defining +around+ callbacks using blocks, you must yield within the
    # transition by directly calling the block (since yielding is not allowed
    # within blocks).
    # 
    # For example,
    # 
    #   class Vehicle
    #     state_machine do
    #       around_transition do |block|
    #         Benchmark.measure { block.call }
    #       end
    #       
    #       around_transition do |vehicle, block|
    #         logger.info "vehicle was #{state}..."
    #         block.call
    #         logger.info "...and is now #{state}"
    #       end
    #       
    #       around_transition do |vehicle, transition, block|
    #         logger.info "before #{transition.event}: #{vehicle.state}"
    #         block.call
    #         logger.info "after #{transition.event}: #{vehicle.state}"
    #       end
    #     end
    #   end
    # 
    # Notice that referencing the block is similar to doing so within an
    # actual method definition in that it is always the last argument.
    # 
    # On the other hand, if you're defining +around+ callbacks using method
    # references, you can yield like normal:
    # 
    #   class Vehicle
    #     state_machine do
    #       around_transition :benchmark
    #       ...
    #     end
    #     
    #     def benchmark
    #       Benchmark.measure { yield }
    #     end
    #   end
    # 
    # See +before_transition+ for a description of the possible configurations
    # for defining callbacks.
    def around_transition(*args, &block)
      options = (args.last.is_a?(Hash) ? args.pop : {})
      options[:do] = args if args.any?
      add_callback(:around, options, &block)
    end
    
    # Creates a callback that will be invoked *after* a transition failures to
    # be performed so long as the given requirements match the transition.
    # 
    # See +before_transition+ for a description of the possible configurations
    # for defining callbacks.  *Note* however that you cannot define the state
    # requirements in these callbacks.  You may only define event requirements.
    # 
    # = The callback
    # 
    # Failure callbacks get invoked whenever an event fails to execute.  This
    # can happen when no transition is available, a +before+ callback halts
    # execution, or the action associated with this machine fails to succeed.
    # In any of these cases, any failure callback that matches the attempted
    # transition will be run.
    # 
    # For example,
    # 
    #   class Vehicle
    #     state_machine do
    #       after_failure do |vehicle, transition|
    #         logger.error "vehicle #{vehicle} failed to transition on #{transition.event}"
    #       end
    #       
    #       after_failure :on => :ignite, :do => :log_ignition_failure
    #       
    #       ...
    #     end
    #   end
    def after_failure(*args, &block)
      options = (args.last.is_a?(Hash) ? args.pop : {})
      options[:do] = args if args.any?
      assert_valid_keys(options, :on, :do, :if, :unless)
      
      add_callback(:failure, options, &block)
    end
    
    # Generates a list of the possible transition sequences that can be run on
    # the given object.  These paths can reveal all of the possible states and
    # events that can be encountered in the object's state machine based on the
    # object's current state.
    # 
    # Configuration options:
    # * +from+ - The initial state to start all paths from.  By default, this
    #   is the object's current state.
    # * +to+ - The target state to end all paths on.  By default, paths will
    #   end when they loop back to the first transition on the path.
    # * +deep+ - Whether to allow the target state to be crossed more than once
    #   in a path.  By default, paths will immediately stop when the target
    #   state (if specified) is reached.  If this is enabled, then paths can
    #   continue even after reaching the target state; they will stop when
    #   reaching the target state a second time.
    # 
    # *Note* that the object is never modified when the list of paths is
    # generated.
    # 
    # == Examples
    # 
    #   class Vehicle
    #     state_machine :initial => :parked do
    #       event :ignite do
    #         transition :parked => :idling
    #       end
    #       
    #       event :shift_up do
    #         transition :idling => :first_gear, :first_gear => :second_gear
    #       end
    #       
    #       event :shift_down do
    #         transition :second_gear => :first_gear, :first_gear => :idling
    #       end
    #     end
    #   end
    #   
    #   vehicle = Vehicle.new   # => #<Vehicle:0xb7c27024 @state="parked">
    #   vehicle.state           # => "parked"
    #   
    #   vehicle.state_paths
    #   # => [
    #   #     [#<StateMachine::Transition attribute=:state event=:ignite from="parked" from_name=:parked to="idling" to_name=:idling>,
    #   #      #<StateMachine::Transition attribute=:state event=:shift_up from="idling" from_name=:idling to="first_gear" to_name=:first_gear>,
    #   #      #<StateMachine::Transition attribute=:state event=:shift_up from="first_gear" from_name=:first_gear to="second_gear" to_name=:second_gear>,
    #   #      #<StateMachine::Transition attribute=:state event=:shift_down from="second_gear" from_name=:second_gear to="first_gear" to_name=:first_gear>,
    #   #      #<StateMachine::Transition attribute=:state event=:shift_down from="first_gear" from_name=:first_gear to="idling" to_name=:idling>],
    #   #       
    #   #     [#<StateMachine::Transition attribute=:state event=:ignite from="parked" from_name=:parked to="idling" to_name=:idling>,
    #   #      #<StateMachine::Transition attribute=:state event=:shift_up from="idling" from_name=:idling to="first_gear" to_name=:first_gear>,
    #   #      #<StateMachine::Transition attribute=:state event=:shift_down from="first_gear" from_name=:first_gear to="idling" to_name=:idling>]
    #   #    ]
    #   
    #   vehicle.state_paths(:from => :parked, :to => :second_gear)
    #   # => [
    #   #     [#<StateMachine::Transition attribute=:state event=:ignite from="parked" from_name=:parked to="idling" to_name=:idling>,
    #   #      #<StateMachine::Transition attribute=:state event=:shift_up from="idling" from_name=:idling to="first_gear" to_name=:first_gear>,
    #   #      #<StateMachine::Transition attribute=:state event=:shift_up from="first_gear" from_name=:first_gear to="second_gear" to_name=:second_gear>]
    #   #    ]
    # 
    # In addition to getting the possible paths that can be accessed, you can
    # also get summary information about the states / events that can be
    # accessed at some point along one of the paths.  For example:
    # 
    #   # Get the list of states that can be accessed from the current state
    #   vehicle.state_paths.to_states # => [:idling, :first_gear, :second_gear]
    #   
    #   # Get the list of events that can be accessed from the current state
    #   vehicle.state_paths.events    # => [:ignite, :shift_up, :shift_down]
    def paths_for(object, requirements = {})
      PathCollection.new(object, self, requirements)
    end
    
    # Marks the given object as invalid with the given message.
    # 
    # By default, this is a no-op.
    def invalidate(object, attribute, message, values = [])
    end
    
    # Gets a description of the errors for the given object.  This is used to
    # provide more detailed information when an InvalidTransition exception is
    # raised.
    def errors_for(object)
      ''
    end
    
    # Resets any errors previously added when invalidating the given object.
    # 
    # By default, this is a no-op.
    def reset(object)
    end
    
    # Generates the message to use when invalidating the given object after
    # failing to transition on a specific event
    def generate_message(name, values = [])
      (@messages[name] || self.class.default_messages[name]) % values.map {|value| value.last}
    end
    
    # Runs a transaction, rolling back any changes if the yielded block fails.
    # 
    # This is only applicable to integrations that involve databases.  By
    # default, this will not run any transactions since the changes aren't
    # taking place within the context of a database.
    def within_transaction(object)
      if use_transactions
        transaction(object) { yield }
      else
        yield
      end
    end
    
    # Draws a directed graph of the machine for visualizing the various events,
    # states, and their transitions.
    # 
    # This requires both the Ruby graphviz gem and the graphviz library be
    # installed on the system.
    # 
    # Configuration options:
    # * <tt>:name</tt> - The name of the file to write to (without the file extension).
    #   Default is "#{owner_class.name}_#{name}"
    # * <tt>:path</tt> - The path to write the graph file to.  Default is the
    #   current directory (".").
    # * <tt>:format</tt> - The image format to generate the graph in.
    #   Default is "png'.
    # * <tt>:font</tt> - The name of the font to draw state names in.
    #   Default is "Arial".
    # * <tt>:orientation</tt> - The direction of the graph ("portrait" or
    #   "landscape").  Default is "portrait".
    # * <tt>:human_names</tt> - Whether to use human state / event names for
    #   node labels on the graph instead of the internal name.  Default is false.
    def draw(options = {})
      options = {
        :name => "#{owner_class.name}_#{name}",
        :path => '.',
        :format => 'png',
        :font => 'Arial',
        :orientation => 'portrait',
        :human_names => false
      }.merge(options)
      assert_valid_keys(options, :name, :path, :format, :font, :orientation, :human_names)
      
      begin
        # Load the graphviz library
        require 'rubygems'
        gem 'ruby-graphviz', '>=0.9.0'
        require 'graphviz'
        
        graph = GraphViz.new('G', :rankdir => options[:orientation] == 'landscape' ? 'LR' : 'TB')
        
        # Add nodes
        states.by_priority.each do |state|
          node = state.draw(graph, :human_name => options[:human_names])
          node.fontname = options[:font]
        end
        
        # Add edges
        events.each do |event|
          edges = event.draw(graph, :human_name => options[:human_names])
          edges.each {|edge| edge.fontname = options[:font]}
        end
        
        # Generate the graph
        graphvizVersion = Constants::RGV_VERSION.split('.')
        file = File.join(options[:path], "#{options[:name]}.#{options[:format]}")
        
        if graphvizVersion[0] == '0' && graphvizVersion[1] == '9' && graphvizVersion[2] == '0'
          outputOptions = {:output => options[:format], :file => file}
        else
          outputOptions = {options[:format] => file}
        end
        
        graph.output(outputOptions)
        graph
      rescue LoadError => ex
        $stderr.puts "Cannot draw the machine (#{ex.message}). `gem install ruby-graphviz` >= v0.9.0 and try again."
        false
      end
    end
    
    # Determines whether an action hook was defined for firing attribute-based
    # event transitions when the configured action gets called.
    def action_hook?(self_only = false)
      @action_hook_defined || !self_only && owner_class.state_machines.any? {|name, machine| machine.action == action && machine != self && machine.action_hook?(true)}
    end
    
    protected
      # Runs additional initialization hooks.  By default, this is a no-op.
      def after_initialize
      end
      
      # Looks up other machines that have been defined in the owner class and
      # are targeting the same attribute as this machine.  When accessing
      # sibling machines, they will be automatically copied for the current
      # class if they haven't been already.  This ensures that any configuration
      # changes made to the sibling machines only affect this class and not any
      # base class that may have originally defined the machine.
      def sibling_machines
        owner_class.state_machines.inject([]) do |machines, (name, machine)|
          if machine.attribute == attribute && machine != self
            machines << (owner_class.state_machine(name) {})
          end
          machines
        end
      end
      
      # Determines if the machine's attribute needs to be initialized.  This
      # will only be true if the machine's attribute is blank.
      def initialize_state?(object)
        value = read(object, :state)
        (value.nil? || value.respond_to?(:empty?) && value.empty?) && !states[value, :value]
      end
      
      # Adds helper methods for interacting with the state machine, including
      # for states, events, and transitions
      def define_helpers
        define_state_accessor
        define_state_predicate
        define_event_helpers
        define_path_helpers
        define_action_helpers if define_action_helpers?
        define_name_helpers
      end
      
      # Defines the initial values for state machine attributes.  Static values
      # are set prior to the original initialize method and dynamic values are
      # set *after* the initialize method in case it is dependent on it.
      def define_state_initializer
        define_helper :instance, <<-end_eval, __FILE__, __LINE__ + 1
          def initialize(*)
            self.class.state_machines.initialize_states(self) { super }
          end
        end_eval
      end
      
      # Adds reader/writer methods for accessing the state attribute
      def define_state_accessor
        attribute = self.attribute
        
        @helper_modules[:instance].class_eval { attr_reader attribute } unless owner_class_ancestor_has_method?(:instance, attribute)
        @helper_modules[:instance].class_eval { attr_writer attribute } unless owner_class_ancestor_has_method?(:instance, "#{attribute}=")
      end
      
      # Adds predicate method to the owner class for determining the name of the
      # current state
      def define_state_predicate
        call_super = !!owner_class_ancestor_has_method?(:instance, "#{name}?")
        define_helper :instance, <<-end_eval, __FILE__, __LINE__ + 1
          def #{name}?(*args)
            args.empty? && (#{call_super} || defined?(super)) ? super : self.class.state_machine(#{name.inspect}).states.matches?(self, *args)
          end
        end_eval
      end
      
      # Adds helper methods for getting information about this state machine's
      # events
      def define_event_helpers
        # Gets the events that are allowed to fire on the current object
        define_helper(:instance, attribute(:events)) do |machine, object, *args|
          machine.events.valid_for(object, *args).map {|event| event.name}
        end
        
        # Gets the next possible transitions that can be run on the current
        # object
        define_helper(:instance, attribute(:transitions)) do |machine, object, *args|
          machine.events.transitions_for(object, *args)
        end
        
        # Fire an arbitrary event for this machine
        define_helper(:instance, "fire_#{attribute(:event)}") do |machine, object, event, *args|
          machine.events.fetch(event).fire(object, *args)
        end
        
        # Add helpers for tracking the event / transition to invoke when the
        # action is called
        if action
          event_attribute = attribute(:event)
          define_helper(:instance, event_attribute) do |machine, object|
            # Interpret non-blank events as present
            event = machine.read(object, :event, true)
            event && !(event.respond_to?(:empty?) && event.empty?) ? event.to_sym : nil
          end
          
          # A roundabout way of writing the attribute is used here so that
          # integrations can hook into this modification
          define_helper(:instance, "#{event_attribute}=") do |machine, object, value|
            machine.write(object, :event, value, true)
          end
          
          event_transition_attribute = attribute(:event_transition)
          define_helper :instance, <<-end_eval, __FILE__, __LINE__ + 1
            protected; attr_accessor #{event_transition_attribute.inspect}
          end_eval
        end
      end
      
      # Adds helper methods for getting information about this state machine's
      # available transition paths
      def define_path_helpers
        # Gets the paths of transitions available to the current object
        define_helper(:instance, attribute(:paths)) do |machine, object, *args|
          machine.paths_for(object, *args)
        end
      end
      
      # Determines whether action helpers should be defined for this machine.
      # This is only true if there is an action configured and no other machines
      # have process this same configuration already.
      def define_action_helpers?
        action && !owner_class.state_machines.any? {|name, machine| machine.action == action && machine != self}
      end
      
      # Adds helper methods for automatically firing events when an action
      # is invoked
      def define_action_helpers
        if action_hook
          @action_hook_defined = true
          define_action_hook
        end
      end
      
      # Hooks directly into actions by defining the same method in an included
      # module.  As a result, when the action gets invoked, any state events
      # defined for the object will get run.  Method visibility is preserved.
      def define_action_hook
        action_hook = self.action_hook
        action = self.action
        private_action_hook = owner_class.private_method_defined?(action_hook)
        
        # Only define helper if it hasn't 
        define_helper :instance, <<-end_eval, __FILE__, __LINE__ + 1
          def #{action_hook}(*)
            self.class.state_machines.transitions(self, #{action.inspect}).perform { super }
          end
          
          private #{action_hook.inspect} if #{private_action_hook}
        end_eval
      end
      
      # The method to hook into for triggering transitions when invoked.  By
      # default, this is the action configured for the machine.
      # 
      # Since the default hook technique relies on module inheritance, the
      # action must be defined in an ancestor of the owner classs in order for
      # it to be the action hook.
      def action_hook
        action && owner_class_ancestor_has_method?(:instance, action) ? action : nil
      end
      
      # Determines whether there's already a helper method defined within the
      # given scope.  This is true only if one of the owner's ancestors defines
      # the method and is further along in the ancestor chain than this
      # machine's helper module.
      def owner_class_ancestor_has_method?(scope, method)
        superclasses = owner_class.ancestors[1..-1].select {|ancestor| ancestor.is_a?(Class)}
        
        if scope == :class
          # Use singleton classes
          current = (class << owner_class; self; end)
          superclass = superclasses.first
        else
          current = owner_class
          superclass = owner_class.superclass
        end
        
        # Generate the list of modules that *only* occur in the owner class, but
        # were included *prior* to the helper modules, in addition to the
        # superclasses
        ancestors = current.ancestors - superclass.ancestors + superclasses
        ancestors = ancestors[ancestors.index(@helper_modules[scope])..-1].reverse
        
        # Search for for the first ancestor that defined this method
        ancestors.detect do |ancestor|
          ancestor = (class << ancestor; self; end) if scope == :class && ancestor.is_a?(Class)
          ancestor.method_defined?(method) || ancestor.private_method_defined?(method)
        end
      end
      
      # Adds helper methods for accessing naming information about states and
      # events on the owner class
      def define_name_helpers
        # Gets the humanized version of a state
        define_helper(:class, "human_#{attribute(:name)}") do |machine, klass, state|
          machine.states.fetch(state).human_name(klass)
        end
        
        # Gets the humanized version of an event
        define_helper(:class, "human_#{attribute(:event_name)}") do |machine, klass, event|
          machine.events.fetch(event).human_name(klass)
        end
        
        # Gets the state name for the current value
        define_helper(:instance, attribute(:name)) do |machine, object|
          machine.states.match!(object).name
        end
        
        # Gets the human state name for the current value
        define_helper(:instance, "human_#{attribute(:name)}") do |machine, object|
          machine.states.match!(object).human_name(object.class)
        end
      end
      
      # Defines the with/without scope helpers for this attribute.  Both the
      # singular and plural versions of the attribute are defined for each
      # scope helper.  A custom plural can be specified if it cannot be
      # automatically determined by either calling +pluralize+ on the attribute
      # name or adding an "s" to the end of the name.
      def define_scopes(custom_plural = nil)
        plural = custom_plural || pluralize(name)
        
        [name, plural].uniq.each do |name|
          [:with, :without].each do |kind|
            method = "#{kind}_#{name}"
            
            if scope = send("create_#{kind}_scope", method)
              # Converts state names to their corresponding values so that they
              # can be looked up properly
              define_helper(:class, method) do |machine, klass, *states|
                run_scope(scope, machine, klass, states)
              end
            end
          end
        end
      end
      
      # Generates the results for the given scope based on one or more states to
      # filter by
      def run_scope(scope, machine, klass, states)
        values = states.flatten.map {|state| machine.states.fetch(state).value}
        scope.call(klass, values)
      end
      
      # Pluralizes the given word using #pluralize (if available) or simply
      # adding an "s" to the end of the word 
      def pluralize(word)
        word = word.to_s
        if word.respond_to?(:pluralize)
          word.pluralize
        else
          "#{name}s"
        end
      end
      
      # Creates a scope for finding objects *with* a particular value or values
      # for the attribute.
      # 
      # By default, this is a no-op.
      def create_with_scope(name)
      end
      
      # Creates a scope for finding objects *without* a particular value or
      # values for the attribute.
      # 
      # By default, this is a no-op.
      def create_without_scope(name)
      end
      
      # Always yields
      def transaction(object)
        yield
      end
      
      # Updates this machine based on the configuration of other machines in the
      # owner class that share the same target attribute.
      def add_sibling_machine_configs
        # Add existing states
        sibling_machines.each do |machine|
          machine.states.each {|state| states << state unless states[state.name]}
        end
      end
      
      # Adds a new transition callback of the given type.
      def add_callback(type, options, &block)
        callbacks[type == :around ? :before : type] << callback = Callback.new(type, options, &block)
        add_states(callback.known_states)
        callback
      end
      
      # Tracks the given set of states in the list of all known states for
      # this machine
      def add_states(new_states)
        new_states.map do |new_state|
          # Check for other states that use a different class type for their name.
          # This typically prevents string / symbol misuse.
          if new_state && conflict = states.detect {|state| state.name && state.name.class != new_state.class}
            raise ArgumentError, "#{new_state.inspect} state defined as #{new_state.class}, #{conflict.name.inspect} defined as #{conflict.name.class}; all states must be consistent"
          end
          
          unless state = states[new_state]
            states << state = State.new(self, new_state)
            
            # Copy states over to sibling machines
            sibling_machines.each {|machine| machine.states << state}
          end
          
          state
        end
      end
      
      # Tracks the given set of events in the list of all known events for
      # this machine
      def add_events(new_events)
        new_events.map do |new_event|
          # Check for other states that use a different class type for their name.
          # This typically prevents string / symbol misuse.
          if conflict = events.detect {|event| event.name.class != new_event.class}
            raise ArgumentError, "#{new_event.inspect} event defined as #{new_event.class}, #{conflict.name.inspect} defined as #{conflict.name.class}; all events must be consistent"
          end
          
          unless event = events[new_event]
            events << event = Event.new(self, new_event)
          end
          
          event
        end
      end
  end
end
