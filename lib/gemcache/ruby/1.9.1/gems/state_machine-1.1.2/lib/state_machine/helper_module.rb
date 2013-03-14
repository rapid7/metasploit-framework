module StateMachine
  # Represents a type of module that defines instance / class methods for a
  # state machine
  class HelperModule < Module #:nodoc:
    def initialize(machine, kind)
      @machine = machine
      @kind = kind
    end
    
    # Provides a human-readable description of the module
    def to_s
      owner_class = @machine.owner_class
      owner_class_name = owner_class.name && !owner_class.name.empty? ? owner_class.name : owner_class.to_s
      "#{owner_class_name} #{@machine.name.inspect} #{@kind} helpers"
    end
  end
end
