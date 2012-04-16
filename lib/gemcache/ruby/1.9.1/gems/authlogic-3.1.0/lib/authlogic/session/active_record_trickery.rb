module Authlogic
  module Session
    # Authlogic looks like ActiveRecord, sounds like ActiveRecord, but its not ActiveRecord. That's the goal here.
    # This is useful for the various rails helper methods such as form_for, error_messages_for, or any method that
    # expects an ActiveRecord object. The point is to disguise the object as an ActiveRecord object so we can take
    # advantage of the many ActiveRecord tools.
    module ActiveRecordTrickery
      def self.included(klass)
        klass.extend ClassMethods
        klass.send(:include, InstanceMethods)
      end
      
      module ClassMethods
        # How to name the attributes of Authlogic, works JUST LIKE ActiveRecord, but instead it uses the following
        # namespace:
        #
        #   authlogic.attributes.user_session.login
        def human_attribute_name(attribute_key_name, options = {})
          options[:count] ||= 1
          options[:default] ||= attribute_key_name.to_s.humanize
          I18n.t("attributes.#{name.underscore}.#{attribute_key_name}", options)
        end
        
        # How to name the class, works JUST LIKE ActiveRecord, except it uses the following namespace:
        #
        #   authlogic.models.user_session
        def human_name(*args)
          I18n.t("models.#{name.underscore}", {:count => 1, :default => name.humanize})
        end
        
        # For rails < 2.3, mispelled
        def self_and_descendents_from_active_record
          [self]
        end
        
        # For rails >= 2.3, mispelling fixed
        def self_and_descendants_from_active_record
          [self]
        end
        
        # For rails >= 3.0
        def model_name
          if defined?(::ActiveModel)
            ::ActiveModel::Name.new(self)
          else
            ::ActiveSupport::ModelName.new(self.to_s)
          end
        end

        def i18n_scope
          I18n.scope
        end

        def lookup_ancestors
          ancestors.select { |x| x.respond_to?(:model_name) }
        end
      end
      
      module InstanceMethods
        # Don't use this yourself, this is to just trick some of the helpers since this is the method it calls.
        def new_record?
          new_session?
        end
        
        # For rails >= 3.0
        def to_model
          self
        end
      end
    end
  end
end
