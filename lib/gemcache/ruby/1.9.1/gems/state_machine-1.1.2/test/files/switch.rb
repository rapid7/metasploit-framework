class Switch
  state_machine do
    event :turn_on do
      transition all => :on
    end
    
    event :turn_off do
      transition all => :off
    end
  end
end
