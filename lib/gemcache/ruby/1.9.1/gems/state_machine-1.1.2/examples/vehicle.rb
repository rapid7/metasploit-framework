require 'state_machine'

class Vehicle
  state_machine :initial => :parked do
    event :park do
      transition [:idling, :first_gear] => :parked
    end
    
    event :ignite do
      transition :stalled => same, :parked => :idling
    end
    
    event :idle do
      transition :first_gear => :idling
    end
    
    event :shift_up do
      transition :idling => :first_gear, :first_gear => :second_gear, :second_gear => :third_gear
    end
    
    event :shift_down do
      transition :third_gear => :second_gear, :second_gear => :first_gear
    end
    
    event :crash do
      transition [:first_gear, :second_gear, :third_gear] => :stalled
    end
    
    event :repair do
      transition :stalled => :parked
    end
  end
end
