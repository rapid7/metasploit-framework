module StateMachine
  # Represents a collection of transitions in a state machine
  class TransitionCollection < Array
    include Assertions
    
    # Whether to skip running the action for each transition's machine
    attr_reader :skip_actions
    
    # Whether to skip running the after callbacks
    attr_reader :skip_after
    
    # Whether transitions should wrapped around a transaction block
    attr_reader :use_transaction
    
    # Creates a new collection of transitions that can be run in parallel.  Each
    # transition *must* be for a different attribute.
    # 
    # Configuration options:
    # * <tt>:actions</tt> - Whether to run the action configured for each transition
    # * <tt>:after</tt> - Whether to run after callbacks
    # * <tt>:transaction</tt> - Whether to wrap transitions within a transaction
    def initialize(transitions = [], options = {})
      super(transitions)
      
      # Determine the validity of the transitions as a whole
      @valid = all?
      reject! {|transition| !transition}
      
      attributes = map {|transition| transition.attribute}.uniq
      raise ArgumentError, 'Cannot perform multiple transitions in parallel for the same state machine attribute' if attributes.length != length
      
      assert_valid_keys(options, :actions, :after, :transaction)
      options = {:actions => true, :after => true, :transaction => true}.merge(options)
      @skip_actions = !options[:actions]
      @skip_after = !options[:after]
      @use_transaction = options[:transaction]
    end
    
    # Runs each of the collection's transitions in parallel.
    # 
    # All transitions will run through the following steps:
    # 1. Before callbacks
    # 2. Persist state
    # 3. Invoke action
    # 4. After callbacks (if configured)
    # 5. Rollback (if action is unsuccessful)
    # 
    # If a block is passed to this method, that block will be called instead
    # of invoking each transition's action.
    def perform(&block)
      reset
      
      if valid?
        if use_event_attributes? && !block_given?
          each do |transition|
            transition.transient = true
            transition.machine.write(object, :event_transition, transition)
          end
          
          run_actions
        else
          within_transaction do
            catch(:halt) { run_callbacks(&block) }
            rollback unless success?
          end
        end
      end
      
      if actions.length == 1 && results.include?(actions.first)
        results[actions.first]
      else
        success?
      end
    end
    
    private
      attr_reader :results #:nodoc:
      
      # Is this a valid set of transitions?  If the collection was creating with
      # any +false+ values for transitions, then the the collection will be
      # marked as invalid.
      def valid?
        @valid
      end
      
      # Did each transition perform successfully?  This will only be true if the
      # following requirements are met:
      # * No +before+ callbacks halt
      # * All actions run successfully (always true if skipping actions)
      def success?
        @success
      end
      
      # Gets the object being transitioned
      def object
        first.object
      end
      
      # Gets the list of actions to run.  If configured to skip actions, then
      # this will return an empty collection.
      def actions
        empty? ? [nil] : map {|transition| transition.action}.uniq
      end
      
      # Determines whether an event attribute be used to trigger the transitions
      # in this collection or whether the transitions be run directly *outside*
      # of the action.
      def use_event_attributes?
        !skip_actions && !skip_after && actions.all? && actions.length == 1 && first.machine.action_hook?
      end
      
      # Resets any information tracked from previous attempts to perform the
      # collection
      def reset
        @results = {}
        @success = false
      end
      
      # Runs each transition's callbacks recursively.  Once all before callbacks
      # have been executed, the transitions will then be persisted and the
      # configured actions will be run.
      # 
      # If any transition fails to run its callbacks, :halt will be thrown.
      def run_callbacks(index = 0, &block)
        if transition = self[index]
          throw :halt unless transition.run_callbacks(:after => !skip_after) do
            run_callbacks(index + 1, &block)
            {:result => results[transition.action], :success => success?}
          end
        else
          persist
          run_actions(&block)
        end
      end
      
      # Transitions the current value of the object's states to those specified by
      # each transition
      def persist
        each {|transition| transition.persist}
      end
      
      # Runs the actions for each transition.  If a block is given method, then it
      # will be called instead of invoking each transition's action.
      # 
      # The results of the actions will be used to determine #success?.
      def run_actions
        catch_exceptions do
          @success = if block_given?
            result = yield
            actions.each {|action| results[action] = result}
            !!result
          else
            actions.compact.each {|action| !skip_actions && results[action] = object.send(action)}
            results.values.all?
          end
        end
      end
      
      # Rolls back changes made to the object's states via each transition
      def rollback
        each {|transition| transition.rollback}
      end
      
      # Wraps the given block with a rescue handler so that any exceptions that
      # occur will automatically result in the transition rolling back any changes
      # that were made to the object involved.
      def catch_exceptions
        begin
          yield
        rescue Exception
          rollback
          raise
        end
      end
      
      # Runs a block within a transaction for the object being transitioned.  If
      # transactions are disabled, then this is a no-op.
      def within_transaction
        if use_transaction && !empty?
          first.within_transaction do
            yield
            success?
          end
        else
          yield
        end
      end
  end
  
  # Represents a collection of transitions that were generated from attribute-
  # based events
  class AttributeTransitionCollection < TransitionCollection
    def initialize(transitions = [], options = {}) #:nodoc:
      super(transitions, {:transaction => false, :actions => false}.merge(options))
    end
    
    private
      # Hooks into running transition callbacks so that event / event transition
      # attributes can be properly updated
      def run_callbacks(index = 0)
        if index == 0
          # Clears any traces of the event attribute to prevent it from being
          # evaluated multiple times if actions are nested
          each do |transition|
            transition.machine.write(object, :event, nil)
            transition.machine.write(object, :event_transition, nil)
          end
          
          # Rollback only if exceptions occur during before callbacks
          begin
            super
          rescue Exception
            rollback unless @before_run
            raise
          end
          
          # Persists transitions on the object if partial transition was successful.
          # This allows us to reference them later to complete the transition with
          # after callbacks.          
          each {|transition| transition.machine.write(object, :event_transition, transition)} if skip_after && success?
        else
          super
        end
      end
      
      # Tracks that before callbacks have now completed
      def persist
        @before_run = true
        super
      end
      
      # Resets callback tracking
      def reset
        super
        @before_run = false
      end
      
      # Resets the event attribute so it can be re-evaluated if attempted again
      def rollback
        super
        each {|transition| transition.machine.write(object, :event, transition.event) unless transition.transient?}
      end
  end
end
