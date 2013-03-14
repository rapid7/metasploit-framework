module StateMachine
  # Provides a set of helper methods for making assertions about the content
  # of various objects
  module Assertions
    # Validates that the given hash *only* includes the specified valid keys.
    # If any invalid keys are found, an ArgumentError will be raised.
    #
    # == Examples
    # 
    #   options = {:name => 'John Smith', :age => 30}
    #   
    #   assert_valid_keys(options, :name)           # => ArgumentError: Invalid key(s): age
    #   assert_valid_keys(options, 'name', 'age')   # => ArgumentError: Invalid key(s): age, name
    #   assert_valid_keys(options, :name, :age)     # => nil
    def assert_valid_keys(hash, *valid_keys)
      invalid_keys = hash.keys - valid_keys
      raise ArgumentError, "Invalid key(s): #{invalid_keys.join(', ')}" unless invalid_keys.empty?
    end
    
    # Validates that the given hash only includes at *most* one of a set of
    # exclusive keys.  If more than one key is found, an ArgumentError will be
    # raised.
    # 
    # == Examples
    # 
    #   options = {:only => :on, :except => :off}
    #   assert_exclusive_keys(options, :only)                   # => nil
    #   assert_exclusive_keys(options, :except)                 # => nil
    #   assert_exclusive_keys(options, :only, :except)          # => ArgumentError: Conflicting keys: only, except
    #   assert_exclusive_keys(options, :only, :except, :with)   # => ArgumentError: Conflicting keys: only, except
    def assert_exclusive_keys(hash, *exclusive_keys)
      conflicting_keys = exclusive_keys & hash.keys
      raise ArgumentError, "Conflicting keys: #{conflicting_keys.join(', ')}" unless conflicting_keys.length <= 1
    end
  end
end
