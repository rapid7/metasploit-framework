module Authlogic
  module ActsAsAuthentic
    # Allows you to scope everything to specific fields.
    # See the Config submodule for more info.
    # For information on how to scope off of a parent object see Authlogic::AuthenticatesMany
    module ValidationsScope
      def self.included(klass)
        klass.class_eval do
          extend Config
        end
      end
      
      # All configuration for the scope feature.
      module Config
        # Allows you to scope everything to specific field(s). Works just like validates_uniqueness_of.
        # For example, let's say a user belongs to a company, and you want to scope everything to the
        # company:
        #
        #   acts_as_authentic do |c|
        #     c.validations_scope = :company_id
        #   end
        #
        # * <tt>Default:</tt> nil
        # * <tt>Accepts:</tt> Symbol or Array of symbols
        def validations_scope(value = nil)
          rw_config(:validations_scope, value)
        end
        alias_method :validations_scope=, :validations_scope
      end
    end
  end
end