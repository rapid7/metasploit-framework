module StateMachine
  module Integrations #:nodoc:
    module Sequel
      version '2.8.x - 3.23.x' do
        def self.active?
          !defined?(::Sequel::MAJOR) || ::Sequel::MAJOR == 2 || ::Sequel::MAJOR == 3 && ::Sequel::MINOR <= 23
        end
        
        def define_state_initializer
          define_helper :instance, <<-end_eval, __FILE__, __LINE__ + 1
            def initialize(*)
              super do |*args|
                self.class.state_machines.initialize_states(self, :static => false)
                changed_columns.clear
                yield(*args) if block_given?
              end
            end
            
            def set(*)
              self.class.state_machines.initialize_states(self, :dynamic => false) if values.empty?
              super
            end
          end_eval
        end
        
        def define_validation_hook
          define_helper :instance, <<-end_eval, __FILE__, __LINE__ + 1
            def valid?(*args)
              yielded = false
              result = self.class.state_machines.transitions(self, :save, :after => false).perform do
                yielded = true
                super
              end
              
              if yielded || result
                result
              else
                #{handle_validation_failure}
              end
            end
          end_eval
        end
        
        def define_action_hook
          if action == :save
            define_helper :instance, <<-end_eval, __FILE__, __LINE__ + 1
              def #{action_hook}(*)
                yielded = false
                result = self.class.state_machines.transitions(self, :save).perform do
                  yielded = true
                  super
                end
                
                if yielded || result
                  result
                else
                  #{handle_save_failure}
                end
              end
            end_eval
          else
            super
          end
        end
        
        def action_hook
          action == :save ? :_save : super
        end
      end
      
      version '2.8.x - 2.11.x' do
        def self.active?
          !defined?(::Sequel::MAJOR) || ::Sequel::MAJOR == 2 && ::Sequel::MINOR <= 11
        end
        
        def load_plugins
        end
        
        def load_inflector
        end
        
        def action_hook
          action == :save ? :save : super
        end
        
        def model_from_dataset(dataset)
          dataset.model_classes[nil]
        end
      end
      
      version '2.8.x - 3.13.x' do
        def self.active?
          !defined?(::Sequel::MAJOR) || ::Sequel::MAJOR == 2 || ::Sequel::MAJOR == 3 && ::Sequel::MINOR <= 13
        end
        
        def handle_validation_failure
          'raise_on_save_failure ? save_failure(:validation) : result'
        end
        
        def handle_save_failure
          'save_failure(:save)'
        end
      end
      
      version '3.14.x - 3.23.x' do
        def self.active?
          defined?(::Sequel::MAJOR) && ::Sequel::MAJOR == 3 && ::Sequel::MINOR >= 14 && ::Sequel::MINOR <= 23
        end
        
        def handle_validation_failure
          'raise_on_failure?(args.first || {}) ? raise_hook_failure(:validation) : result'
        end
        
        def handle_save_failure
          'raise_hook_failure(:save)'
        end
      end
    end
  end
end
