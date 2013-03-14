module StateMachine
  module Integrations #:nodoc:
    module MongoMapper
      version '0.5.x - 0.6.x' do
        def self.active?
          !defined?(::MongoMapper::Plugins)
        end
        
        def filter_attributes(object, attributes)
          attributes
        end
        
        def define_state_initializer
          define_helper :instance, <<-end_eval, __FILE__, __LINE__ + 1
            def initialize(*args)
              attrs, * = args
              attrs && attrs.stringify_keys.key?('_id') ? super : self.class.state_machines.initialize_states(self) { super }
            end
          end_eval
        end
      end
      
      version '0.5.x - 0.7.x' do
        def self.active?
          !defined?(::MongoMapper::Version) || ::MongoMapper::Version =~ /^0\.[5-7]\./
        end
        
        def define_scope(name, scope)
          lambda {|model, values| model.all(scope.call(values))}
        end
      end
      
      version '0.5.x - 0.8.x' do
        def self.active?
          !defined?(::MongoMapper::Version) || ::MongoMapper::Version =~ /^0\.[5-8]\./
        end
        
        def invalidate(object, attribute, message, values = [])
          object.errors.add(self.attribute(attribute), generate_message(message, values))
        end
        
        def define_state_accessor
          owner_class.key(attribute, String) unless owner_class.keys.include?(attribute)
          
          name = self.name
          owner_class.validates_each(attribute, :logic => lambda {|*|
            machine = self.class.state_machine(name)
            machine.invalidate(self, :state, :invalid) unless machine.states.match(self)
          })
        end
        
        def action_hook
          action == :save ? :create_or_update : super
        end
        
        def load_locale
        end
        
        def supports_observers?
          false
        end
        
        def supports_validations?
          true
        end
        
        def callback_terminator
        end
        
        def translate(klass, key, value)
          value.to_s.humanize.downcase
        end
      end
      
      version '0.7.x - 0.8.3' do
        def self.active?
          # Only 0.8.x and up has a Version string available, so Plugins is used
          # to detect when 0.7.x is active
          defined?(::MongoMapper::Plugins) && (!defined?(::MongoMapper::Version) || ::MongoMapper::Version =~ /^0\.(7|8\.[0-3])\./)
        end
        
        def define_state_initializer
          define_helper :instance, <<-end_eval, __FILE__, __LINE__ + 1
            def initialize(*args)
              attrs, from_db = args
              from_db ? super : self.class.state_machines.initialize_states(self) { super }
            end
          end_eval
        end
      end
      
      # Assumes MongoMapper 0.10+ uses ActiveModel 3.1+
      version '0.9.x' do
        def self.active?
          defined?(::MongoMapper::Version) && ::MongoMapper::Version =~ /^0\.9\./
        end
        
        def define_action_hook
          # +around+ callbacks don't have direct access to results until AS 3.1
          owner_class.set_callback(:save, :after, 'value', :prepend => true) if action_hook == :save
          super
        end
      end
    end
  end
end
