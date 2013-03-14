module StateMachine
  # Provides a set of helper methods for generating matchers
  module MatcherHelpers
    # Represents a state that matches all known states in a machine.
    # 
    # == Examples
    # 
    #   class Vehicle
    #     state_machine do
    #       before_transition any => :parked, :do => lambda {...}
    #       before_transition all - :parked => all - :idling, :do => lambda {}
    #       
    #       event :park
    #         transition all => :parked
    #       end
    #       
    #       event :crash
    #         transition all - :parked => :stalled
    #       end
    #     end
    #   end
    # 
    # In the above example, +all+ will match the following states since they
    # are known:
    # * +parked+
    # * +stalled+
    # * +idling+
    def all
      AllMatcher.instance
    end
    alias_method :any, :all
    
    # Represents a state that matches the original +from+ state.  This is useful
    # for defining transitions which are loopbacks.
    # 
    # == Examples
    # 
    #   class Vehicle
    #     state_machine do
    #       event :ignite
    #         transition [:idling, :first_gear] => same
    #       end
    #     end
    #   end
    # 
    # In the above example, +same+ will match whichever the from state is.  In
    # the case of the +ignite+ event, it is essential the same as the following:
    # 
    #   transition :parked => :parked, :first_gear => :first_gear
    def same
      LoopbackMatcher.instance
    end
  end
end
