module StateMachine
  module Integrations #:nodoc:
    module ActiveRecord
      version '2.x - 3.0.x' do
        def self.active?
          ::ActiveRecord::VERSION::MAJOR == 2 || ::ActiveRecord::VERSION::MAJOR == 3 && ::ActiveRecord::VERSION::MINOR == 0
        end
        
        def define_static_state_initializer
          define_helper :instance, <<-end_eval, __FILE__, __LINE__ + 1
            def attributes_from_column_definition(*)
              result = super
              self.class.state_machines.initialize_states(self, :dynamic => false, :to => result)
              result
            end
          end_eval
        end
      end
      
      version '2.x' do
        def self.active?
          ::ActiveRecord::VERSION::MAJOR == 2
        end
        
        def load_locale
          super if defined?(I18n)
        end
        
        def create_scope(name, scope)
          if owner_class.respond_to?(:named_scope)
            name = name.to_sym
            machine_name = self.name
            
            # Since ActiveRecord does not allow direct access to the model
            # being used within the evaluation of a dynamic named scope, the
            # scope must be generated manually.  It's necessary to have access
            # to the model so that the state names can be translated to their
            # associated values and so that inheritance is respected properly.
            owner_class.named_scope(name)
            owner_class.scopes[name] = lambda do |model, *states|
              machine_states = model.state_machine(machine_name).states
              values = states.flatten.map {|state| machine_states.fetch(state).value}
              
              ::ActiveRecord::NamedScope::Scope.new(model, :conditions => scope.call(values))
            end
          end
          
          # Prevent the Machine class from wrapping the scope
          false
        end
        
        def invalidate(object, attribute, message, values = [])
          if defined?(I18n)
            super
          else
            object.errors.add(self.attribute(attribute), generate_message(message, values))
          end
        end
        
        def translate(klass, key, value)
          if defined?(I18n)
            super
          else
            value ? value.to_s.humanize.downcase : 'nil'
          end
        end
        
        def supports_observers?
          true
        end
        
        def supports_validations?
          true
        end
        
        def supports_mass_assignment_security?
          true
        end
        
        def i18n_scope(klass)
          :activerecord
        end
        
        def action_hook
          action == :save ? :create_or_update : super
        end
        
        def load_observer_extensions
          super
          ::ActiveRecord::Observer.class_eval do
            include StateMachine::Integrations::ActiveModel::Observer
          end unless ::ActiveRecord::Observer < StateMachine::Integrations::ActiveModel::Observer
        end
      end
      
      version '2.0 - 2.2.x' do
        def self.active?
          ::ActiveRecord::VERSION::MAJOR == 2 && ::ActiveRecord::VERSION::MINOR < 3
        end
        
        def default_error_message_options(object, attribute, message)
          {:default => @messages[message]}
        end
      end
      
      version '2.0 - 2.3.1' do
        def self.active?
          ::ActiveRecord::VERSION::MAJOR == 2 && (::ActiveRecord::VERSION::MINOR < 3 || ::ActiveRecord::VERSION::TINY < 2)
        end
        
        def ancestors_for(klass)
          klass.self_and_descendents_from_active_record
        end
      end
      
      version '2.3.2 - 2.3.x' do
        def self.active?
          ::ActiveRecord::VERSION::MAJOR == 2 && ::ActiveRecord::VERSION::MINOR == 3 && ::ActiveRecord::VERSION::TINY >= 2
        end
        
        def ancestors_for(klass)
          klass.self_and_descendants_from_active_record
        end
      end
      
      version '3.0.x' do
        def self.active?
          ::ActiveRecord::VERSION::MAJOR == 3 && ::ActiveRecord::VERSION::MINOR == 0
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
