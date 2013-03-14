module StateMachine
  module Integrations #:nodoc:
    module ActiveModel
      # Represents the encapsulation of all of the details to be included in an
      # update to state machine observers.  This allows multiple arguments to
      # get passed to an observer method (instead of just a single +object+)
      # while still respecting the way in which ActiveModel checks for the
      # object's list of observers.
      class ObserverUpdate
        # The method to invoke on the observer
        attr_reader :method
        
        # The object being transitioned
        attr_reader :object
        
        # The transition being run
        attr_reader :transition
        
        def initialize(method, object, transition) #:nodoc:
          @method, @object, @transition = method, object, transition
        end
        
        # The arguments to pass into the method
        def args
          [object, transition]
        end
        
        # The class of the object being transitioned.  Normally the object
        # getting passed into observer methods is the actual instance of the
        # ActiveModel class.  ActiveModel uses that instance's class to check
        # for enabled / disabled observers.
        # 
        # Since state_machine is passing an ObserverUpdate instance into observer
        # methods, +class+ needs to be overridden so that ActiveModel can still
        # get access to the enabled / disabled observers.
        def class
          object.class
        end
      end
    end
  end
end
