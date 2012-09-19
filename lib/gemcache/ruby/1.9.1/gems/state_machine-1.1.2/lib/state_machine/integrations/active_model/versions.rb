module StateMachine
  module Integrations #:nodoc:
    module ActiveModel
      version '2.x' do
        def self.active?
          !defined?(::ActiveModel::VERSION) || ::ActiveModel::VERSION::MAJOR == 2
        end
        
        def define_validation_hook
          define_helper :instance, <<-end_eval, __FILE__, __LINE__ + 1
            def valid?(*)
              self.class.state_machines.transitions(self, #{action.inspect}, :after => false).perform { super }
            end
          end_eval
        end
      end
      
      version '3.0.x' do
        def self.active?
          defined?(::ActiveModel::VERSION) && ::ActiveModel::VERSION::MAJOR == 3 && ::ActiveModel::VERSION::MINOR == 0
        end
        
        def define_validation_hook
          # +around+ callbacks don't have direct access to results until AS 3.1
          owner_class.set_callback(:validation, :after, 'value', :prepend => true)
          super
        end
      end
    end
  end
end
