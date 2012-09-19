class User
  include DataMapper::Resource
  
  property :id, Serial
  property :name, String
  
  validates_present :name, :state, :access_state
  
  state_machine :initial => :unregistered do
    event :register do
      transition :unregistered => :registered
    end
    
    event :unregister do
      transition :registered => :unregistered
    end
  end
  
  state_machine :access_state, :initial => :enabled do
    event :enable do
      transition all => :enabled
    end
    
    event :disable do
      transition all => :disabled
    end
  end
end
