module StateMachine
  module Integrations #:nodoc:
    module Mongoid
      version '2.0.x - 2.2.x' do
        def self.active?
          ::Mongoid::VERSION =~ /^2\.[0-2]\./
        end
        
        def define_state_initializer
          define_helper :instance, <<-end_eval, __FILE__, __LINE__ + 1
            # Initializes dynamic states
            def initialize(*)
              super do |*args|
                self.class.state_machines.initialize_states(self, :static => false)
                yield(*args) if block_given?
              end
            end
            
            # Initializes static states
            def apply_default_attributes(*)
              result = super
              self.class.state_machines.initialize_states(self, :dynamic => false, :to => result) if new_record?
              result
            end
          end_eval
        end
        
        def define_action_hook
          # +around+ callbacks don't have direct access to results until AS 3.1
          owner_class.set_callback(:save, :after, 'value', :prepend => true) if action_hook == :save
          super
        end
      end
      
      version '2.0.x' do
        def self.active?
          ::Mongoid::VERSION =~ /^2\.0\./
        end
        
        # Forces the change in state to be recognized regardless of whether the
        # state value actually changed
        def write(object, attribute, value, *args)
          result = super
          
          if (attribute == :state || attribute == :event && value) && !object.send("#{self.attribute}_changed?")
            current = read(object, :state)
            object.changes[self.attribute.to_s] = [attribute == :event ? current : value, current]
          end
          
          result
        end
      end
    end
  end
end
