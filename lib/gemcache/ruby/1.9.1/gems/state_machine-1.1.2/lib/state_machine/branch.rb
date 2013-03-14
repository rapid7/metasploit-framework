require 'state_machine/matcher'
require 'state_machine/eval_helpers'
require 'state_machine/assertions'

module StateMachine
  # Represents a set of requirements that must be met in order for a transition
  # or callback to occur.  Branches verify that the event, from state, and to
  # state of the transition match, in addition to if/unless conditionals for
  # an object's state.
  class Branch
    include Assertions
    include EvalHelpers
    
    # The condition that must be met on an object
    attr_reader :if_condition
    
    # The condition that must *not* be met on an object
    attr_reader :unless_condition
    
    # The requirement for verifying the event being matched
    attr_reader :event_requirement
    
    # One or more requirements for verifying the states being matched.  All
    # requirements contain a mapping of {:from => matcher, :to => matcher}.
    attr_reader :state_requirements
    
    # A list of all of the states known to this branch.  This will pull states
    # from the following options (in the same order):
    # * +from+ / +except_from+
    # * +to+ / +except_to+
    attr_reader :known_states
    
    # Creates a new branch
    def initialize(options = {}) #:nodoc:
      # Build conditionals
      @if_condition = options.delete(:if)
      @unless_condition = options.delete(:unless)
      
      # Build event requirement
      @event_requirement = build_matcher(options, :on, :except_on)
      
      if (options.keys - [:from, :to, :on, :except_from, :except_to, :except_on]).empty?
        # Explicit from/to requirements specified
        @state_requirements = [{:from => build_matcher(options, :from, :except_from), :to => build_matcher(options, :to, :except_to)}]
      else
        # Separate out the event requirement
        options.delete(:on)
        options.delete(:except_on)
        
        # Implicit from/to requirements specified
        @state_requirements = options.collect do |from, to|
          from = WhitelistMatcher.new(from) unless from.is_a?(Matcher)
          to = WhitelistMatcher.new(to) unless to.is_a?(Matcher)
          {:from => from, :to => to}
        end
      end
      
      # Track known states.  The order that requirements are iterated is based
      # on the priority in which tracked states should be added.
      @known_states = []
      @state_requirements.each do |state_requirement|
        [:from, :to].each {|option| @known_states |= state_requirement[option].values}
      end
    end
    
    # Determines whether the given object / query matches the requirements
    # configured for this branch.  In addition to matching the event, from state,
    # and to state, this will also check whether the configured :if/:unless
    # conditions pass on the given object.
    # 
    # == Examples
    # 
    #   branch = StateMachine::Branch.new(:parked => :idling, :on => :ignite)
    #   
    #   # Successful
    #   branch.matches?(object, :on => :ignite)                                   # => true
    #   branch.matches?(object, :from => nil)                                     # => true
    #   branch.matches?(object, :from => :parked)                                 # => true
    #   branch.matches?(object, :to => :idling)                                   # => true
    #   branch.matches?(object, :from => :parked, :to => :idling)                 # => true
    #   branch.matches?(object, :on => :ignite, :from => :parked, :to => :idling) # => true
    #   
    #   # Unsuccessful
    #   branch.matches?(object, :on => :park)                                     # => false
    #   branch.matches?(object, :from => :idling)                                 # => false
    #   branch.matches?(object, :to => :first_gear)                               # => false
    #   branch.matches?(object, :from => :parked, :to => :first_gear)             # => false
    #   branch.matches?(object, :on => :park, :from => :parked, :to => :idling)   # => false
    def matches?(object, query = {})
      !match(object, query).nil?
    end
    
    # Attempts to match the given object / query against the set of requirements
    # configured for this branch.  In addition to matching the event, from state,
    # and to state, this will also check whether the configured :if/:unless
    # conditions pass on the given object.
    # 
    # If a match is found, then the event/state requirements that the query
    # passed successfully will be returned.  Otherwise, nil is returned if there
    # was no match.
    # 
    # Query options:
    # * <tt>:from</tt> - One or more states being transitioned from.  If none
    #   are specified, then this will always match.
    # * <tt>:to</tt> - One or more states being transitioned to.  If none are
    #   specified, then this will always match.
    # * <tt>:on</tt> - One or more events that fired the transition.  If none
    #   are specified, then this will always match.
    # * <tt>:guard</tt> - Whether to guard matches with the if/unless
    #   conditionals defined for this branch.  Default is true.
    # 
    # == Examples
    # 
    #   branch = StateMachine::Branch.new(:parked => :idling, :on => :ignite)
    #   
    #   branch.match(object, :on => :ignite)  # => {:to => ..., :from => ..., :on => ...}
    #   branch.match(object, :on => :park)    # => nil
    def match(object, query = {})
      assert_valid_keys(query, :from, :to, :on, :guard)
      
      if (match = match_query(query)) && matches_conditions?(object, query)
        match
      end
    end
    
    # Draws a representation of this branch on the given graph.  This will draw
    # an edge between every state this branch matches *from* to either the
    # configured to state or, if none specified, then a loopback to the from
    # state.
    # 
    # For example, if the following from states are configured:
    # * +idling+
    # * +first_gear+
    # * +backing_up+
    # 
    # ...and the to state is +parked+, then the following edges will be created:
    # * +idling+      -> +parked+
    # * +first_gear+  -> +parked+
    # * +backing_up+  -> +parked+
    # 
    # Each edge will be labeled with the name of the event that would cause the
    # transition.
    # 
    # The collection of edges generated on the graph will be returned.
    def draw(graph, event, valid_states)
      state_requirements.inject([]) do |edges, state_requirement|
        # From states determined based on the known valid states
        from_states = state_requirement[:from].filter(valid_states)
        
        # If a to state is not specified, then it's a loopback and each from
        # state maps back to itself
        if state_requirement[:to].values.empty?
          loopback = true
        else
          to_state = state_requirement[:to].values.first
          to_state = to_state ? to_state.to_s : 'nil'
          loopback = false
        end
        
        # Generate an edge between each from and to state
        from_states.each do |from_state|
          from_state = from_state ? from_state.to_s : 'nil'
          edges << graph.add_edge(from_state, loopback ? from_state : to_state, :label => event.to_s)
        end
        
        edges
      end
    end
    
    protected
      # Builds a matcher strategy to use for the given options.  If neither a
      # whitelist nor a blacklist option is specified, then an AllMatcher is
      # built.
      def build_matcher(options, whitelist_option, blacklist_option)
        assert_exclusive_keys(options, whitelist_option, blacklist_option)
        
        if options.include?(whitelist_option)
          WhitelistMatcher.new(options[whitelist_option])
        elsif options.include?(blacklist_option)
          BlacklistMatcher.new(options[blacklist_option])
        else
          AllMatcher.instance
        end
      end
      
      # Verifies that all configured requirements (event and state) match the
      # given query.  If a match is found, then a hash containing the
      # event/state requirements that passed will be returned; otherwise, nil.
      def match_query(query)
        query ||= {}
        
        if match_event(query) && (state_requirement = match_states(query))
          state_requirement.merge(:on => event_requirement)
        end
      end
      
      # Verifies that the event requirement matches the given query
      def match_event(query)
        matches_requirement?(query, :on, event_requirement)
      end
      
      # Verifies that the state requirements match the given query.  If a
      # matching requirement is found, then it is returned.
      def match_states(query)
        state_requirements.detect do |state_requirement|
          [:from, :to].all? {|option| matches_requirement?(query, option, state_requirement[option])}
        end
      end
      
      # Verifies that an option in the given query matches the values required
      # for that option
      def matches_requirement?(query, option, requirement)
        !query.include?(option) || requirement.matches?(query[option], query)
      end
      
      # Verifies that the conditionals for this branch evaluate to true for the
      # given object
      def matches_conditions?(object, query)
        query[:guard] == false ||
        Array(if_condition).all? {|condition| evaluate_method(object, condition)} &&
        !Array(unless_condition).any? {|condition| evaluate_method(object, condition)}
      end
  end
end
