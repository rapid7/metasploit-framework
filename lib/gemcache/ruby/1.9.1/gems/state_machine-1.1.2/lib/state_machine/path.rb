module StateMachine
  # A path represents a sequence of transitions that can be run for a particular
  # object.  Paths can walk to new transitions, revealing all of the possible
  # branches that can be encountered in the object's state machine.
  class Path < Array
    include Assertions
    
    # The object whose state machine is being walked
    attr_reader :object
    
    # The state machine this path is walking
    attr_reader :machine
    
    # Creates a new transition path for the given object.  Initially this is an
    # empty path.  In order to start walking the path, it must be populated with
    # an initial transition.
    # 
    # Configuration options:
    # * <tt>:target</tt> - The target state to end the path on
    # * <tt>:guard</tt> - Whether to guard transitions with the if/unless
    #   conditionals defined for each one
    def initialize(object, machine, options = {})
      assert_valid_keys(options, :target, :guard)
      
      @object = object
      @machine = machine
      @target = options[:target]
      @guard = options[:guard]
    end
    
    def initialize_copy(orig) #:nodoc:
      super
      @transitions = nil
    end
    
    # The initial state name for this path
    def from_name
      first && first.from_name
    end
    
    # Lists all of the from states that can be reached through this path.
    # 
    # For example,
    # 
    #   path.to_states  # => [:parked, :idling, :first_gear, ...]
    def from_states
      map {|transition| transition.from_name}.uniq
    end
    
    # The end state name for this path.  If a target state was specified for
    # the path, then that will be returned if the path is complete.
    def to_name
      last && last.to_name
    end
    
    # Lists all of the to states that can be reached through this path.
    # 
    # For example,
    # 
    #   path.to_states  # => [:parked, :idling, :first_gear, ...]
    def to_states
      map {|transition| transition.to_name}.uniq
    end
    
    # Lists all of the events that can be fired through this path.
    # 
    # For example,
    # 
    #   path.events # => [:park, :ignite, :shift_up, ...]
    def events
      map {|transition| transition.event}.uniq
    end
    
    # Walks down the next transitions at the end of this path.  This will only
    # walk down paths that are considered valid.
    def walk
      transitions.each {|transition| yield dup.push(transition)}
    end
    
    # Determines whether or not this path has completed.  A path is considered
    # complete when one of the following conditions is met:
    # * The last transition in the path ends on the target state
    # * There are no more transitions remaining to walk and there is no target
    #   state
    def complete?
      !empty? && (@target ? to_name == @target : transitions.empty?)
    end
    
    private
      # Calculates the number of times the given state has been walked to
      def times_walked_to(state)
        select {|transition| transition.to_name == state}.length
      end
      
      # Determines whether the given transition has been recently walked down in
      # this path.  If a target is configured for this path, then this will only
      # look at transitions walked down since the target was last reached.
      def recently_walked?(transition)
        transitions = self
        if @target && @target != to_name && target_transition = detect {|t| t.to_name == @target}
          transitions = transitions[index(target_transition) + 1..-1]
        end
        transitions.include?(transition)
      end
      
      # Determines whether it's possible to walk to the given transition from
      # the current path.  A transition can be walked to if:
      # * It has not been recently walked and
      # * If a target is specified, it has not been walked to twice yet
      def can_walk_to?(transition)
        !recently_walked?(transition) && (!@target || times_walked_to(@target) < 2)
      end
      
      # Get the next set of transitions that can be walked to starting from the
      # end of this path
      def transitions
        @transitions ||= empty? ? [] : machine.events.transitions_for(object, :from => to_name, :guard => @guard).select {|transition| can_walk_to?(transition)}
      end
  end
end
