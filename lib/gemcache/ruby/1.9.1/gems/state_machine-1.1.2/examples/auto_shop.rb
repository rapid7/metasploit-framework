require 'state_machine'

class AutoShop
  state_machine :initial => :available do
    event :tow_vehicle do
      transition :available => :busy
    end
    
    event :fix_vehicle do
      transition :busy => :available 
    end
  end
end
