require 'state_machine/transition_collection'
require 'state_machine/error'

module StateMachine
  # An invalid transition was attempted
  class InvalidTransition < Error
    # The machine attempting to be transitioned
    attr_reader :machine
    
    # The current state value for the machine
    attr_reader :from
    
    def initialize(object, machine, event) #:nodoc:
      @machine = machine
      @from_state = machine.states.match!(object)
      @from = machine.read(object, :state)
      @event = machine.events.fetch(event)
      errors = machine.errors_for(object)
      
      message = "Cannot transition #{machine.name} via :#{self.event} from #{from_name.inspect}"
      message << " (Reason(s): #{errors})" unless errors.empty?
      super(object, message)
    end
    
    # The event that triggered the failed transition
    def event
      @event.name
    end
    
    # The fully-qualified name of the event that triggered the failed transition
    def qualified_event
      @event.qualified_name
    end
    
    # The name for the current state
    def from_name
      @from_state.name
    end
    
    # The fully-qualified name for the current state
    def qualified_from_name
      @from_state.qualified_name
    end
  end
  
  # A set of transition failed to run in parallel
  class InvalidParallelTransition < Error
    # The set of events that failed the transition(s)
    attr_reader :events
    
    def initialize(object, events) #:nodoc:
      @events = events
      
      super(object, "Cannot run events in parallel: #{events * ', '}")
    end
  end
  
  # A transition represents a state change for a specific attribute.
  # 
  # Transitions consist of:
  # * An event
  # * A starting state
  # * An ending state
  class Transition
    # The object being transitioned
    attr_reader :object
    
    # The state machine for which this transition is defined
    attr_reader :machine
    
    # The original state value *before* the transition
    attr_reader :from
    
    # The new state value *after* the transition
    attr_reader :to
    
    # The arguments passed in to the event that triggered the transition
    # (does not include the +run_action+ boolean argument if specified)
    attr_accessor :args
    
    # The result of invoking the action associated with the machine
    attr_reader :result
    
    # Whether the transition is only existing temporarily for the object
    attr_writer :transient
    
    # Creates a new, specific transition
    def initialize(object, machine, event, from_name, to_name, read_state = true) #:nodoc:
      @object = object
      @machine = machine
      @args = []
      @transient = false
      
      @event = machine.events.fetch(event)
      @from_state = machine.states.fetch(from_name)
      @from = read_state ? machine.read(object, :state) : @from_state.value
      @to_state = machine.states.fetch(to_name)
      @to = @to_state.value
      
      reset
    end
    
    # The attribute which this transition's machine is defined for
    def attribute
      machine.attribute
    end
    
    # The action that will be run when this transition is performed
    def action
      machine.action
    end
    
    # The event that triggered the transition
    def event
      @event.name
    end
    
    # The fully-qualified name of the event that triggered the transition
    def qualified_event
      @event.qualified_name
    end
    
    # The human-readable name of the event that triggered the transition
    def human_event
      @event.human_name(@object.class)
    end
    
    # The state name *before* the transition
    def from_name
      @from_state.name
    end
    
    # The fully-qualified state name *before* the transition
    def qualified_from_name
      @from_state.qualified_name
    end
    
    # The human-readable state name *before* the transition
    def human_from_name
      @from_state.human_name(@object.class)
    end
    
    # The new state name *after* the transition
    def to_name
      @to_state.name
    end
    
    # The new fully-qualified state name *after* the transition
    def qualified_to_name
      @to_state.qualified_name
    end
    
    # The new human-readable state name *after* the transition
    def human_to_name
      @to_state.human_name(@object.class)
    end
    
    # Does this transition represent a loopback (i.e. the from and to state
    # are the same)
    # 
    # == Example
    # 
    #   machine = StateMachine.new(Vehicle)
    #   StateMachine::Transition.new(Vehicle.new, machine, :park, :parked, :parked).loopback?   # => true
    #   StateMachine::Transition.new(Vehicle.new, machine, :park, :idling, :parked).loopback?   # => false
    def loopback?
      from_name == to_name
    end
    
    # Is this transition existing for a short period only?  If this is set, it
    # indicates that the transition (or the event backing it) should not be
    # written to the object if it fails.
    def transient?
      @transient
    end
    
    # A hash of all the core attributes defined for this transition with their
    # names as keys and values of the attributes as values.
    # 
    # == Example
    # 
    #   machine = StateMachine.new(Vehicle)
    #   transition = StateMachine::Transition.new(Vehicle.new, machine, :ignite, :parked, :idling)
    #   transition.attributes   # => {:object => #<Vehicle:0xb7d60ea4>, :attribute => :state, :event => :ignite, :from => 'parked', :to => 'idling'}
    def attributes
      @attributes ||= {:object => object, :attribute => attribute, :event => event, :from => from, :to => to}
    end
    
    # Runs the actual transition and any before/after callbacks associated
    # with the transition.  The action associated with the transition/machine
    # can be skipped by passing in +false+.
    # 
    # == Examples
    # 
    #   class Vehicle
    #     state_machine :action => :save do
    #       ...
    #     end
    #   end
    #   
    #   vehicle = Vehicle.new
    #   transition = StateMachine::Transition.new(vehicle, machine, :ignite, :parked, :idling)
    #   transition.perform                  # => Runs the +save+ action after setting the state attribute
    #   transition.perform(false)           # => Only sets the state attribute
    #   transition.perform(Time.now)        # => Passes in additional arguments and runs the +save+ action
    #   transition.perform(Time.now, false) # => Passes in additional arguments and only sets the state attribute
    def perform(*args)
      run_action = [true, false].include?(args.last) ? args.pop : true
      self.args = args
      
      # Run the transition
      !!TransitionCollection.new([self], :actions => run_action).perform
    end
    
    # Runs a block within a transaction for the object being transitioned.
    # By default, transactions are a no-op unless otherwise defined by the
    # machine's integration.
    def within_transaction
      machine.within_transaction(object) do
        yield
      end
    end
    
    # Runs the before / after callbacks for this transition.  If a block is
    # provided, then it will be executed between the before and after callbacks.
    # 
    # Configuration options:
    # * +before+ - Whether to run before callbacks.
    # * +after+ - Whether to run after callbacks.  If false, then any around
    #   callbacks will be paused until called again with +after+ enabled.
    #   Default is true.
    # 
    # This will return true if all before callbacks gets executed.  After
    # callbacks will not have an effect on the result.
    def run_callbacks(options = {}, &block)
      options = {:before => true, :after => true}.merge(options)
      @success = false
      
      halted = pausable { before(options[:after], &block) } if options[:before]
      
      # After callbacks are only run if:
      # * An around callback didn't halt after yielding
      # * They're enabled or the run didn't succeed
      after if !(@before_run && halted) && (options[:after] || !@success)
      
      @before_run
    end
    
    # Transitions the current value of the state to that specified by the
    # transition.  Once the state is persisted, it cannot be persisted again
    # until this transition is reset.
    # 
    # == Example
    # 
    #   class Vehicle
    #     state_machine do
    #       event :ignite do
    #         transition :parked => :idling
    #       end
    #     end
    #   end
    #   
    #   vehicle = Vehicle.new
    #   transition = StateMachine::Transition.new(vehicle, Vehicle.state_machine, :ignite, :parked, :idling)
    #   transition.persist
    #   
    #   vehicle.state   # => 'idling'
    def persist
      unless @persisted
        machine.write(object, :state, to)
        @persisted = true
      end
    end
    
    # Rolls back changes made to the object's state via this transition.  This
    # will revert the state back to the +from+ value.
    # 
    # == Example
    # 
    #   class Vehicle
    #     state_machine :initial => :parked do
    #       event :ignite do
    #         transition :parked => :idling
    #       end
    #     end
    #   end
    #   
    #   vehicle = Vehicle.new     # => #<Vehicle:0xb7b7f568 @state="parked">
    #   transition = StateMachine::Transition.new(vehicle, Vehicle.state_machine, :ignite, :parked, :idling)
    #   
    #   # Persist the new state
    #   vehicle.state             # => "parked"
    #   transition.persist
    #   vehicle.state             # => "idling"
    #   
    #   # Roll back to the original state
    #   transition.rollback
    #   vehicle.state             # => "parked"
    def rollback
      reset
      machine.write(object, :state, from)
    end
    
    # Resets any tracking of which callbacks have already been run and whether
    # the state has already been persisted
    def reset
      @before_run = @persisted = @after_run = false
      @paused_block = nil
    end
    
    # Determines equality of transitions by testing whether the object, states,
    # and event involved in the transition are equal
    def ==(other)
      other.instance_of?(self.class) &&
      other.object == object &&
      other.machine == machine &&
      other.from_name == from_name &&
      other.to_name == to_name &&
      other.event == event
    end
    
    # Generates a nicely formatted description of this transitions's contents.
    # 
    # For example,
    # 
    #   transition = StateMachine::Transition.new(object, machine, :ignite, :parked, :idling)
    #   transition   # => #<StateMachine::Transition attribute=:state event=:ignite from="parked" from_name=:parked to="idling" to_name=:idling>
    def inspect
      "#<#{self.class} #{%w(attribute event from from_name to to_name).map {|attr| "#{attr}=#{send(attr).inspect}"} * ' '}>"
    end
    
    private
      # Runs a block that may get paused.  If the block doesn't pause, then
      # execution will continue as normal.  If the block gets paused, then it
      # will take care of switching the execution context when it's resumed.
      # 
      # This will return true if the given block halts for a reason other than
      # getting paused.
      def pausable
        begin
          halted = !catch(:halt) { yield; true }
        rescue Exception => error
          raise unless @resume_block
        end
        
        if @resume_block
          @resume_block.call(halted, error)
        else
          halted
        end
      end
      
      # Pauses the current callback execution.  This should only occur within
      # around callbacks when the remainder of the callback will be executed at
      # a later point in time.
      def pause
        raise ArgumentError, 'around_transition callbacks cannot be called in multiple execution contexts in java implementations of Ruby. Use before/after_transitions instead.' if RUBY_PLATFORM == 'java'
        
        unless @resume_block
          require 'continuation' unless defined?(callcc)
          callcc do |block|
            @paused_block = block
            throw :halt, true
          end
        end
      end
      
      # Resumes the execution of a previously paused callback execution.  Once
      # the paused callbacks complete, the current execution will continue.
      def resume
        if @paused_block
          halted, error = callcc do |block|
            @resume_block = block
            @paused_block.call
          end
          
          @resume_block = @paused_block = nil
          
          raise error if error
          !halted
        else
          true
        end
      end
      
      # Runs the machine's +before+ callbacks for this transition.  Only
      # callbacks that are configured to match the event, from state, and to
      # state will be invoked.
      # 
      # Once the callbacks are run, they cannot be run again until this transition
      # is reset.
      def before(complete = true, index = 0, &block)
        unless @before_run
          while callback = machine.callbacks[:before][index]
            index += 1
            
            if callback.type == :around
              # Around callback: need to handle recursively.  Execution only gets
              # paused if:
              # * The block fails and the callback doesn't run on failures OR
              # * The block succeeds, but after callbacks are disabled (in which
              #   case a continuation is stored for later execution)
              return if catch(:cancel) do
                callback.call(object, context, self) do
                  before(complete, index, &block)
                  
                  pause if @success && !complete
                  throw :cancel, true unless @success
                end
              end
            else
              # Normal before callback
              callback.call(object, context, self)
            end
          end
          
          @before_run = true
        end
        
        action = {:success => true}.merge(block_given? ? yield : {})
        @result, @success = action[:result], action[:success]
      end
      
      # Runs the machine's +after+ callbacks for this transition.  Only
      # callbacks that are configured to match the event, from state, and to
      # state will be invoked.
      # 
      # Once the callbacks are run, they cannot be run again until this transition
      # is reset.
      # 
      # == Halting
      # 
      # If any callback throws a <tt>:halt</tt> exception, it will be caught
      # and the callback chain will be automatically stopped.  However, this
      # exception will not bubble up to the caller since +after+ callbacks
      # should never halt the execution of a +perform+.
      def after
        unless @after_run
          # First resume previously paused callbacks
          if resume
            catch(:halt) do
              type = @success ? :after : :failure
              machine.callbacks[type].each {|callback| callback.call(object, context, self)}
            end
          end
          
          @after_run = true
        end
      end
      
      # Gets a hash of the context defining this unique transition (including
      # event, from state, and to state).
      # 
      # == Example
      # 
      #   machine = StateMachine.new(Vehicle)
      #   transition = StateMachine::Transition.new(Vehicle.new, machine, :ignite, :parked, :idling)
      #   transition.context    # => {:on => :ignite, :from => :parked, :to => :idling}
      def context
        @context ||= {:on => event, :from => from_name, :to => to_name}
      end
  end
end
