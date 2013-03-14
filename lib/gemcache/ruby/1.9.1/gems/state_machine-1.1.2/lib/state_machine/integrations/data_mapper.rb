module StateMachine
  module Integrations #:nodoc:
    # Adds support for integrating state machines with DataMapper resources.
    # 
    # == Examples
    # 
    # Below is an example of a simple state machine defined within a
    # DataMapper resource:
    # 
    #   class Vehicle
    #     include DataMapper::Resource
    #     
    #     property :id, Serial
    #     property :name, String
    #     property :state, String
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
    # is the +save+ action.  This will cause the resource to save the changes
    # made to the state machine's attribute.  *Note* that if any other changes
    # were made to the resource prior to transition, then those changes will
    # be saved as well.
    # 
    # For example,
    # 
    #   vehicle = Vehicle.create          # => #<Vehicle id=1 name=nil state="parked">
    #   vehicle.name = 'Ford Explorer'
    #   vehicle.ignite                    # => true
    #   vehicle.reload                    # => #<Vehicle id=1 name="Ford Explorer" state="idling">
    # 
    # == Events
    # 
    # As described in StateMachine::InstanceMethods#state_machine, event
    # attributes are created for every machine that allow transitions to be
    # performed automatically when the object's action (in this case, :save)
    # is called.
    # 
    # In DataMapper, these automated events are run in the following order:
    # * before validation - If validation feature loaded, run before callbacks and persist new states, then validate
    # * before save - If validation feature was skipped/not loaded, run before callbacks and persist new states, then save
    # * after save - Run after callbacks
    # 
    # For example,
    # 
    #   vehicle = Vehicle.create          # => #<Vehicle id=1 name=nil state="parked">
    #   vehicle.state_event               # => nil
    #   vehicle.state_event = 'invalid'
    #   vehicle.valid?                    # => false
    #   vehicle.errors                    # => #<DataMapper::Validate::ValidationErrors:0xb7a48b54 @errors={"state_event"=>["is invalid"]}>
    #   
    #   vehicle.state_event = 'ignite'
    #   vehicle.valid?                    # => true
    #   vehicle.save                      # => true
    #   vehicle.state                     # => "idling"
    #   vehicle.state_event               # => nil
    # 
    # Note that this can also be done on a mass-assignment basis:
    # 
    #   vehicle = Vehicle.create(:state_event => 'ignite')  # => #<Vehicle id=1 name=nil state="idling">
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
    #     include DataMapper::Resource
    #     ...
    #     
    #     state_machine do
    #       ...
    #     end
    #     protected :state_event
    #   end
    # 
    # If you want to only have *some* events be able to fire via mass-assignment,
    # you can build two state machines (one public and one protected) like so:
    # 
    #   class Vehicle
    #     include DataMapper::Resource
    #     ...
    #     
    #     state_machine do
    #       # Define private events here
    #     end
    #     protected :state_event= # Prevent access to events in the first machine
    #     
    #     # Allow both machines to share the same state
    #     state_machine :public_state, :attribute => :state do
    #       # Define public events here
    #     end
    #   end
    # 
    # === Within DataMapper Hooks
    # 
    # DataMapper protects against the potential for system stack errors resulting
    # from infinite loops by preventing records from being saved multiple times
    # within save hooks.  You need to be acutely aware of this when interacting
    # with state_machine within save hooks.  There are two things to keep in mind:
    # 
    # 1. You cannot run a state_machine event during an `after :save/:create` hook.
    # 2. If you need to run a state_machine event during a `before :save/:create/etc.`
    #    hook, then you have to force the machine's action to be skipped by passing
    #    `false` in as an argument to the event.
    # 
    # For example:
    # 
    #   class Vehicle
    #     include DataMapper::Resource
    #     ...
    #     
    #     state_machine :initial => :parked do
    #       event :ignite do
    #         transition :parked => :idling
    #       end
    #     end
    #     
    #     # This will allow the event to transition without attempting to save a second time
    #     before :create { ignite(false) }
    #     
    #     # This will never work because DataMapper will refuse to save the
    #     # changes since we're still inside of a transaction
    #     # after :create { ignite }
    #   end
    # 
    # While the above will work, in reality you should typically just set the
    # `state_event` attribute in `#initialize` to automatically transition an
    # object on creation.
    # 
    # == Transactions
    # 
    # By default, the use of transactions during an event transition is
    # turned off to be consistent with DataMapper.  This means that if
    # changes are made to the database during a before callback, but the
    # transition fails to complete, those changes will *not* be rolled back.
    # 
    # For example,
    # 
    #   class Message
    #     include DataMapper::Resource
    #     
    #     property :id, Serial
    #     property :content, String
    #   end
    #   
    #   Vehicle.state_machine do
    #     before_transition do |transition|
    #       Message.create(:content => transition.inspect)
    #       throw :halt
    #     end
    #   end
    #   
    #   vehicle = Vehicle.create      # => #<Vehicle id=1 name=nil state="parked">
    #   vehicle.ignite                # => false
    #   Message.all.count             # => 1
    # 
    # To turn on transactions:
    # 
    #   class Vehicle
    #     include DataMapper::Resource
    #     ...
    #     
    #     state_machine :initial => :parked, :use_transactions => true do
    #       ...
    #     end
    #   end
    # 
    # If using the +save+ action for the machine, this option will be ignored as
    # the transaction behavior will depend on the +save+ implementation within
    # DataMapper.  To avoid this, use a different action like so:
    # 
    #   class Vehicle
    #     include DataMapper::Resource
    #     ...
    #     
    #     state_machine :initial => :parked, :use_transactions => false, :action => :save_state do
    #       ...
    #     end
    #     
    #     alias_method :save_state, :save
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
    #   vehicle = Vehicle.create(:state => 'idling')  # => #<Vehicle id=1 name=nil state="idling">
    #   vehicle.ignite                                # => false
    #   vehicle.errors.full_messages                  # => ["cannot transition via \"ignite\""]
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
    # To assist in filtering models with specific states, a series of class
    # methods are defined on the model for finding records with or without a
    # particular set of states.
    # 
    # These named scopes are the functional equivalent of the following
    # definitions:
    # 
    #   class Vehicle
    #     include DataMapper::Resource
    #     
    #     property :id, Serial
    #     property :state, String
    #     
    #     class << self
    #       def with_states(*states)
    #         all(:state => states.flatten)
    #       end
    #       alias_method :with_state, :with_states
    #       
    #       def without_states(*states)
    #         all(:state.not => states.flatten)
    #       end
    #       alias_method :without_state, :without_states
    #     end
    #   end
    # 
    # *Note*, however, that the states are converted to their stored values
    # before being passed into the query.
    # 
    # Because of the way scopes work in DataMapper, they can be chained like
    # so:
    # 
    #   Vehicle.with_state(:parked).all(:order => [:id.desc])
    # 
    # Note that states can also be referenced by the string version of their
    # name:
    # 
    #   Vehicle.with_state('parked')
    # 
    # == Callbacks / Observers
    # 
    # All before/after transition callbacks defined for DataMapper resources
    # behave in the same way that other DataMapper hooks behave.  Rather than
    # passing in the record as an argument to the callback, the callback is
    # instead bound to the object and evaluated within its context.
    # 
    # For example,
    # 
    #   class Vehicle
    #     include DataMapper::Resource
    #     
    #     property :id, Serial
    #     property :state, String
    #     
    #     state_machine :initial => :parked do
    #       before_transition any => :idling do
    #         put_on_seatbelt
    #       end
    #       
    #       before_transition do |transition|
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
    # In addition to support for DataMapper-like hooks, there is additional
    # support for DataMapper observers.  See StateMachine::Integrations::DataMapper::Observer
    # for more information.
    # 
    # === Failure callbacks
    # 
    # +after_failure+ callbacks allow you to execute behaviors when a transition
    # is allowed, but fails to save.  This could be useful for something like
    # auditing transition attempts.  Since callbacks run within transactions in
    # DataMapper, a save failure will cause any records that get created in
    # your callback to roll back.  *Note* that this is only a problem if the
    # machine is configured to use transactions.  If it is, you can work around
    # this issue like so:
    # 
    #   DataMapper.setup(:default, 'mysql://localhost/app')
    #   DataMapper.setup(:logs, 'mysql://localhost/app')
    #   
    #   class TransitionLog
    #     include DataMapper::Resource
    #   end
    #   
    #   class Vehicle < ActiveRecord::Base
    #     include DataMapper::Resource
    #     
    #     state_machine :use_transactions => true do
    #       after_failure do |transition|
    #         DataMapper.repository(:logs) do
    #           TransitionLog.create(:vehicle => vehicle, :transition => transition)
    #         end
    #       end
    #       
    #       ...
    #     end
    #   end
    # 
    # The failure callback creates +TransitionLog+ records using a second
    # connection to the database, allowing them to be saved without being
    # affected by rollbacks in the +Vehicle+ resource's transaction.
    module DataMapper
      include Base
      
      require 'state_machine/integrations/data_mapper/versions'
      
      # The default options to use for state machines using this integration
      @defaults = {:action => :save, :use_transactions => false}
      
      # Classes that include DataMapper::Resource will automatically use the
      # DataMapper integration.
      def self.matching_ancestors
        %w(DataMapper::Resource)
      end
      
      # Loads additional files specific to DataMapper
      def self.extended(base) #:nodoc:
        require 'dm-core/version' unless ::DataMapper.const_defined?('VERSION')
        super
      end
      
      # Adds a validation error to the given object
      def invalidate(object, attribute, message, values = [])
        object.errors.add(self.attribute(attribute), generate_message(message, values)) if supports_validations?
      end
      
      # Describes the current validation errors on the given object.  If none
      # are specific, then the default error is interpeted as a "halt".
      def errors_for(object)
        if object.errors.empty?
          'Transition halted'
        else
          errors = []
          object.errors.each_pair do |field_name, field_errors|
            field_errors.each {|error| errors << "#{field_name} #{error}"}
          end
          errors * ', '
        end
      end
      
      # Resets any errors previously added when invalidating the given object
      def reset(object)
        object.errors.clear if supports_validations?
      end
      
      protected
        # Initializes class-level extensions and defaults for this machine
        def after_initialize
          super
          load_observer_extensions
        end
        
        # Loads extensions to DataMapper's Observers
        def load_observer_extensions
          require 'state_machine/integrations/data_mapper/observer' if ::DataMapper.const_defined?('Observer')
        end
        
        # Is validation support currently loaded?
        def supports_validations?
          @supports_validations ||= ::DataMapper.const_defined?('Validate')
        end
        
        # Pluralizes the name using the built-in inflector
        def pluralize(word)
          ::DataMapper::Inflector.pluralize(word.to_s)
        end
        
        # Defines an initialization hook into the owner class for setting the
        # initial state of the machine *before* any attributes are set on the
        # object
        def define_state_initializer
          define_helper :instance, <<-end_eval, __FILE__, __LINE__ + 1
            def initialize(*args)
              self.class.state_machines.initialize_states(self) { super }
            end
          end_eval
        end
        
        # Skips defining reader/writer methods since this is done automatically
        def define_state_accessor
          owner_class.property(attribute, String) unless owner_class.properties.detect {|property| property.name == attribute}
          
          if supports_validations?
            name = self.name
            owner_class.validates_with_block(attribute) do
              machine = self.class.state_machine(name)
              machine.states.match(self) ? true : [false, machine.generate_message(:invalid)]
            end
          end
        end
        
        # Adds hooks into validation for automatically firing events
        def define_action_helpers
          super
          
          if action == :save && supports_validations?
            define_helper :instance, <<-end_eval, __FILE__, __LINE__ + 1
              def valid?(*)
                self.class.state_machines.transitions(self, :save, :after => false).perform { super }
              end
            end_eval
          end
        end
        
        # Uses internal save hooks if using the :save action
        def action_hook
          action == :save ? :save_self : super
        end
        
        # Creates a scope for finding records *with* a particular state or
        # states for the attribute
        def create_with_scope(name)
          lambda {|resource, values| resource.all(attribute => values)}
        end
        
        # Creates a scope for finding records *without* a particular state or
        # states for the attribute
        def create_without_scope(name)
          lambda {|resource, values| resource.all(attribute.to_sym.not => values)}
        end
        
        # Runs a new database transaction, rolling back any changes if the
        # yielded block fails (i.e. returns false).
        def transaction(object)
          object.class.transaction {|t| t.rollback unless yield}
        end
        
        # Creates a new callback in the callback chain, always ensuring that
        # it's configured to bind to the object as this is the convention for
        # DataMapper/Extlib callbacks
        def add_callback(type, options, &block)
          options[:bind_to_object] = true
          super
        end
    end
  end
end
