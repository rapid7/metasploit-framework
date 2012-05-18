module Authlogic
  module ActsAsAuthentic
    # Maintains the persistence token, the token responsible for persisting sessions. This token
    # gets stores in the session and the cookie.
    module PersistenceToken
      def self.included(klass)
        klass.class_eval do
          add_acts_as_authentic_module(Methods)
        end
      end
      
      # Methods for the persistence token.
      module Methods
        def self.included(klass)
          klass.class_eval do
            extend ClassMethods
            include InstanceMethods
            
            if respond_to?(:after_password_set) && respond_to?(:after_password_verification)
              after_password_set :reset_persistence_token
              after_password_verification :reset_persistence_token!, :if => :reset_persistence_token?
            end
            
            validates_presence_of :persistence_token
            validates_uniqueness_of :persistence_token, :if => :persistence_token_changed?
            
            before_validation :reset_persistence_token, :if => :reset_persistence_token?
          end
        end
        
        # Class level methods for the persistence token.
        module ClassMethods
          # Resets ALL persistence tokens in the database, which will require all users to reauthenticate.
          def forget_all
            # Paginate these to save on memory
            records = nil
            i = 0
            begin
              records = find(:all, :limit => 50, :offset => i)
              records.each { |record| record.forget! }
              i += 50
            end while !records.blank?
          end
        end
        
        # Instance level methods for the persistence token.
        module InstanceMethods
          # Resets the persistence_token field to a random hex value.
          def reset_persistence_token
            self.persistence_token = Authlogic::Random.hex_token
          end
          
          # Same as reset_persistence_token, but then saves the record.
          def reset_persistence_token!
            reset_persistence_token
            save_without_session_maintenance(:validate => false)
          end
          alias_method :forget!, :reset_persistence_token!
          
          private
            def reset_persistence_token?
              persistence_token.blank?
            end
        end
      end
    end
  end
end