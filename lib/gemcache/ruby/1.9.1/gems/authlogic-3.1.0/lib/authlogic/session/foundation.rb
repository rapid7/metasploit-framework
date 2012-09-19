module Authlogic
  module Session
    # Sort of like an interface, it sets the foundation for the class, such as the required methods. This also allows
    # other modules to overwrite methods and call super on them. It's also a place to put "utility" methods used
    # throughout Authlogic.
    module Foundation
      def self.included(klass)
        klass.class_eval do
          class_attribute :acts_as_authentic_config
          self.acts_as_authentic_config  ||= {}
          
          extend ClassMethods
          include InstanceMethods
        end
      end
      
      module ClassMethods
        private
          def rw_config(key, value, default_value = nil, read_value = nil)
            if value == read_value
              return acts_as_authentic_config[key] if acts_as_authentic_config.include?(key)
              rw_config(key, default_value)
            else
              config = acts_as_authentic_config.clone
              config[key] = value
              self.acts_as_authentic_config = config
              value
            end
          end
      end
      
      module InstanceMethods
        def initialize(*args)
          self.credentials = args
        end
        
        # The credentials you passed to create your session. See credentials= for more info.
        def credentials
          []
        end

        # Set your credentials before you save your session. You can pass a hash of credentials:
        #
        #   session.credentials = {:login => "my login", :password => "my password", :remember_me => true}
        #
        # or you can pass an array of objects:
        #
        #   session.credentials = [my_user_object, true]
        #
        # and if you need to set an id, just pass it last. This value need be the last item in the array you pass, since the id is something that
        # you control yourself, it should never be set from a hash or a form. Examples:
        #
        #   session.credentials = [{:login => "my login", :password => "my password", :remember_me => true}, :my_id]
        #   session.credentials = [my_user_object, true, :my_id]
        def credentials=(values)
        end
        
        def inspect
          "#<#{self.class.name}: #{credentials.blank? ? "no credentials provided" : credentials.inspect}>"
        end
        
        def persisted?
          !(new_record? || destroyed?)
        end
        
        def to_key
          new_record? ? nil : [ self.send(self.class.primary_key) ]
        end
        
        private
          def build_key(last_part)
            last_part
          end
      end
    end
  end
end