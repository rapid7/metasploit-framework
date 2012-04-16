module StateMachine
  # An error occurred during a state machine invocation
  class Error < StandardError
    # The object that failed
    attr_reader :object
    
    def initialize(object, message = nil) #:nodoc:
      @object = object
      
      super(message)
    end
  end
end
