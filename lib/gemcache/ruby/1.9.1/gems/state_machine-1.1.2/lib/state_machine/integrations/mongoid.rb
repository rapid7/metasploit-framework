module StateMachine
  module Integrations #:nodoc:
    # Adds support for integrating state machines with Mongoid models.
    # 
    # == Examples
    # 
    # Below is an example of a simple state machine defined within a
    # Mongoid model:
    # 
    #   class Vehicle
    #     include Mongoid::Document
    #     
    #     state_machine :initial => :parked do
    #       event :ignite do
    #         transition :parked => :idling
    #       end
    #     end
    #   end
    # 
    # The examples in the sections below will use the above class as a
    # reference.
    # 
    # == Actions
    # 
    # By default, the action that will be invoked when a state is transitioned
    # is the +save+ action.  This will cause the record to save the changes
    # made to the state machine's attribute.  *Note* that if any other changes
    # were made to the record prior to transition, then those changes will
    # be saved as well.
    # 
    # For example,
    # 
    #   vehicle = Vehicle.create          # => #<Vehicle _id: 4d70e028b876bb54d9000003, name: nil, state: "parked">
    #   vehicle.name = 'Ford Explorer'
    #   vehicle.ignite                    # => true
    #   vehicle.reload                    # => #<Vehicle _id: 4d70e028b876bb54d9000003, name: "Ford Explorer", state: "idling">
    # 
    # == Events
    # 
    # As described in StateMachine::InstanceMethods#state_machine, event
    # attributes are created for every machine that allow transitions to be
    # performed automatically when the object's action (in this case, :save)
    # is called.
    # 
    # In Mongoid, these automated events are run in the following order:
    # * before validation - Run before callbacks and persist new states, then validate
    # * before save - If validation was skipped, run before callbacks and persist new states, then save
    # * after save - Run after callbacks
    # 
    # For example,
    # 
    #   vehicle = Vehicle.create          # => #<Vehicle _id: 4d70e028b876bb54d9000003, name: nil, state: "parked">
    #   vehicle.state_event               # => nil
    #   vehicle.state_event = 'invalid'
    #   vehicle.valid?                    # => false
    #   vehicle.errors.full_messages      # => ["State event is invalid"]
    #   
    #   vehicle.state_event = 'ignite'
    #   vehicle.valid?                    # => true
    #   vehicle.save                      # => true
    #   vehicle.state                     # => "idling"
    #   vehicle.state_event               # => nil
    # 
    # Note that this can also be done on a mass-assignment basis:
    # 
    #   vehicle = Vehicle.create(:state_event => 'ignite')  # => #<Vehicle _id: 4d70e028b876bb54d9000003, name: nil, state: "idling">
    #   vehicle.state                                       # => "idling"
    # 
    # This technique is always used for transitioning states when the +save+
    # action (which is the default) is configured for the machine.
    # 
    # === Security implications
    # 
    # Beware that public event attributes mean that events can be fired
    # whenever mass-assignment is being used.  If you want to prevent malicious
    # users from tampering with events through URLs / forms, the attribute
    # should be protected like so:
    # 
    #   class Vehicle
    #     include Mongoid::Document
    #     
    #     attr_protected :state_event
    #     # attr_accessible ... # Alternative technique
    #     
    #     state_machine do
    #       ...
    #     end
    #   end
    # 
    # If you want to only have *some* events be able to fire via mass-assignment,
    # you can build two state machines (one public and one protected) like so:
    # 
    #   class Vehicle
    #     include Mongoid::Document
    #     
    #     attr_protected :state_event # Prevent access to events in the first machine
    #     
    #     state_machine do
    #       # Define private events here
    #     end
    #     
    #     # Public machine targets the same state as the private machine
    #     state_machine :public_state, :attribute => :state do
    #       # Define public events here
    #     end
    #   end
    # 
    # == Validations
    # 
    # As mentioned in StateMachine::Machine#state, you can define behaviors,
    # like validations, that only execute for certain states. One *important*
    # caveat here is that, due to a constraint in Mongoid's validation
    # framework, custom validators will not work as expected when defined to run
    # in multiple states.  For example:
    # 
    #   class Vehicle
    #     include Mongoid::Document
    #     
    #     state_machine do
    #       ...
    #       state :first_gear, :second_gear do
    #         validate :speed_is_legal
    #       end
    #     end
    #   end
    # 
    # In this case, the <tt>:speed_is_legal</tt> validation will only get run
    # for the <tt>:second_gear</tt> state.  To avoid this, you can define your
    # custom validation like so:
    # 
    #   class Vehicle
    #     include Mongoid::Document
    #     
    #     state_machine do
    #       ...
    #       state :first_gear, :second_gear do
    #         validate {|vehicle| vehicle.speed_is_legal}
    #       end
    #     end
    #   end
    # 
    # == Validation errors
    # 
    # If an event fails to successfully fire because there are no matching
    # transitions for the current record, a validation error is added to the
    # record's state attribute to help in determining why it failed and for
    # reporting via the UI.
    # 
    # For example,
    # 
    #   vehicle = Vehicle.create(:state => 'idling')  # => #<Vehicle _id: 4d70e028b876bb54d9000003, name: nil, state: "idling">
    #   vehicle.ignite                                # => false
    #   vehicle.errors.full_messages                  # => ["State cannot transition via \"ignite\""]
    # 
    # If an event fails to fire because of a validation error on the record and
    # *not* because a matching transition was not available, no error messages
    # will be added to the state attribute.
    # 
    # In addition, if you're using the <tt>ignite!</tt> version of the event,
    # then the failure reason (such as the current validation errors) will be
    # included in the exception that gets raised when the event fails.  For
    # example, assuming there's a validation on a field called +name+ on the class:
    # 
    #   vehicle = Vehicle.new
    #   vehicle.ignite!       # => StateMachine::InvalidTransition: Cannot transition state via :ignite from :parked (Reason(s): Name cannot be blank)
    # 
    # == Scopes
    # 
    # To assist in filtering models with specific states, a series of basic
    # scopes are defined on the model for finding records with or without a
    # particular set of states.
    # 
    # These scopes are essentially the functional equivalent of the following
    # definitions:
    # 
    #   class Vehicle
    #     include Mongoid::Document
    #     
    #     scope :with_states, lambda {|*states| where(:state => {'$in' => states})}
    #     # with_states also aliased to with_state
    #     
    #     scope :without_states, lambda {|*states| where(:state => {'$nin' => states})}
    #     # without_states also aliased to without_state
    #   end
    # 
    # *Note*, however, that the states are converted to their stored values
    # before being passed into the query.
    # 
    # Because of the way named scopes work in Mongoid, they *cannot* be
    # chained.
    # 
    # Note that states can also be referenced by the string version of their
    # name:
    # 
    #   Vehicle.with_state('parked')
    # 
    # == Callbacks
    # 
    # All before/after transition callbacks defined for Mongoid models
    # behave in the same way that other Mongoid callbacks behave.  The
    # object involved in the transition is passed in as an argument.
    # 
    # For example,
    # 
    #   class Vehicle
    #     include Mongoid::Document
    #     
    #     state_machine :initial => :parked do
    #       before_transition any => :idling do |vehicle|
    #         vehicle.put_on_seatbelt
    #       end
    #       
    #       before_transition do |vehicle, transition|
    #         # log message
    #       end
    #       
    #       event :ignite do
    #         transition :parked => :idling
    #       end
    #     end
    #     
    #     def put_on_seatbelt
    #       ...
    #     end
    #   end
    # 
    # Note, also, that the transition can be accessed by simply defining
    # additional arguments in the callback block.
    # 
    # == Observers
    # 
    # In addition to support for Mongoid-like hooks, there is additional support
    # for Mongoid observers.  Because of the way Mongoid observers are designed,
    # there is less flexibility around the specific transitions that can be
    # hooked in.  However, a large number of hooks *are* supported.  For
    # example, if a transition for a record's +state+ attribute changes the
    # state from +parked+ to +idling+ via the +ignite+ event, the following
    # observer methods are supported:
    # * before/after/after_failure_to-_ignite_from_parked_to_idling
    # * before/after/after_failure_to-_ignite_from_parked
    # * before/after/after_failure_to-_ignite_to_idling
    # * before/after/after_failure_to-_ignite
    # * before/after/after_failure_to-_transition_state_from_parked_to_idling
    # * before/after/after_failure_to-_transition_state_from_parked
    # * before/after/after_failure_to-_transition_state_to_idling
    # * before/after/after_failure_to-_transition_state
    # * before/after/after_failure_to-_transition
    # 
    # The following class shows an example of some of these hooks:
    # 
    #   class VehicleObserver < Mongoid::Observer
    #     def before_save(vehicle)
    #       # log message
    #     end
    #     
    #     # Callback for :ignite event *before* the transition is performed
    #     def before_ignite(vehicle, transition)
    #       # log message
    #     end
    #     
    #     # Callback for :ignite event *after* the transition has been performed
    #     def after_ignite(vehicle, transition)
    #       # put on seatbelt
    #     end
    #     
    #     # Generic transition callback *before* the transition is performed
    #     def after_transition(vehicle, transition)
    #       Audit.log(vehicle, transition)
    #     end
    #   end
    # 
    # More flexible transition callbacks can be defined directly within the
    # model as described in StateMachine::Machine#before_transition
    # and StateMachine::Machine#after_transition.
    # 
    # To define a single observer for multiple state machines:
    # 
    #   class StateMachineObserver < Mongoid::Observer
    #     observe Vehicle, Switch, Project
    #     
    #     def after_transition(record, transition)
    #       Audit.log(record, transition)
    #     end
    #   end
    # 
    # == Internationalization
    # 
    # Any error message that is generated from performing invalid transitions
    # can be localized.  The following default translations are used:
    # 
    #   en:
    #     mongoid:
    #       errors:
    #         messages:
    #           invalid: "is invalid"
    #           # %{value} = attribute value, %{state} = Human state name
    #           invalid_event: "cannot transition when %{state}"
    #           # %{value} = attribute value, %{event} = Human event name, %{state} = Human current state name
    #           invalid_transition: "cannot transition via %{event}"
    # 
    # You can override these for a specific model like so:
    # 
    #   en:
    #     mongoid:
    #       errors:
    #         models:
    #           user:
    #             invalid: "is not valid"
    # 
    # In addition to the above, you can also provide translations for the
    # various states / events in each state machine.  Using the Vehicle example,
    # state translations will be looked for using the following keys, where
    # +model_name+ = "vehicle", +machine_name+ = "state" and +state_name+ = "parked":
    # * <tt>mongoid.state_machines.#{model_name}.#{machine_name}.states.#{state_name}</tt>
    # * <tt>mongoid.state_machines.#{model_name}.states.#{state_name}</tt>
    # * <tt>mongoid.state_machines.#{machine_name}.states.#{state_name}</tt>
    # * <tt>mongoid.state_machines.states.#{state_name}</tt>
    # 
    # Event translations will be looked for using the following keys, where
    # +model_name+ = "vehicle", +machine_name+ = "state" and +event_name+ = "ignite":
    # * <tt>mongoid.state_machines.#{model_name}.#{machine_name}.events.#{event_name}</tt>
    # * <tt>mongoid.state_machines.#{model_name}.events.#{event_name}</tt>
    # * <tt>mongoid.state_machines.#{machine_name}.events.#{event_name}</tt>
    # * <tt>mongoid.state_machines.events.#{event_name}</tt>
    # 
    # An example translation configuration might look like so:
    # 
    #   es:
    #     mongoid:
    #       state_machines:
    #         states:
    #           parked: 'estacionado'
    #         events:
    #           park: 'estacionarse'
    module Mongoid
      include Base
      include ActiveModel
      
      require 'state_machine/integrations/mongoid/versions'
      
      # The default options to use for state machines using this integration
      @defaults = {:action => :save}
      
      # Classes that include Mongoid::Document will automatically use the
      # Mongoid integration.
      def self.matching_ancestors
        %w(Mongoid::Document)
      end
      
      def self.extended(base) #:nodoc:
        require 'mongoid/version'
        super
      end
      
      protected
        # Only runs validations on the action if using <tt>:save</tt>
        def runs_validations_on_action?
          action == :save
        end
        
        # Defines an initialization hook into the owner class for setting the
        # initial state of the machine *before* any attributes are set on the
        # object
        def define_state_initializer
          define_helper :instance, <<-end_eval, __FILE__, __LINE__ + 1
            def initialize(*)
              @attributes ||= {}
              self.class.state_machines.initialize_states(self, :dynamic => false)
              
              super do |*args|
                self.class.state_machines.initialize_states(self, :static => false)
                yield(*args) if block_given?
              end
            end
          end_eval
        end
        
        # Skips defining reader/writer methods since this is done automatically
        def define_state_accessor
          owner_class.field(attribute, :type => String) unless owner_class.fields.include?(attribute.to_s)
          super
        end
        
        # Uses around callbacks to run state events if using the :save hook
        def define_action_hook
          if action_hook == :save
            owner_class.set_callback(:save, :around, self, :prepend => true)
          else
            super
          end
        end
        
        # Runs state events around the machine's :save action
        def around_save(object)
          object.class.state_machines.transitions(object, action).perform { yield }
        end
        
        # Creates a scope for finding records *with* a particular state or
        # states for the attribute
        def create_with_scope(name)
          define_scope(name, lambda {|values| {attribute => {'$in' => values}}})
        end
        
        # Creates a scope for finding records *without* a particular state or
        # states for the attribute
        def create_without_scope(name)
          define_scope(name, lambda {|values| {attribute => {'$nin' => values}}})
        end
        
        # Defines a new scope with the given name
        def define_scope(name, scope)
          lambda {|model, values| model.criteria.where(scope.call(values))}
        end
    end
  end
end
