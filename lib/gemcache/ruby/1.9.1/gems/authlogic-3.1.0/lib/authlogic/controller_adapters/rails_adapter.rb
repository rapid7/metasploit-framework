module Authlogic
  module ControllerAdapters
    # Adapts authlogic to work with rails. The point is to close the gap between what authlogic expects and what the rails controller object
    # provides. Similar to how ActiveRecord has an adapter for MySQL, PostgreSQL, SQLite, etc.
    class RailsAdapter < AbstractAdapter
      class AuthlogicLoadedTooLateError < StandardError; end
      
      def authenticate_with_http_basic(&block)
        controller.authenticate_with_http_basic(&block)
      end
      
      def cookies
        controller.send(:cookies)
      end
      
      def cookie_domain
        @cookie_domain_key ||= Rails::VERSION::STRING >= '2.3' ? :domain : :session_domain
        controller.request.session_options[@cookie_domain_key]
      end
      
      def request_content_type
        request.format.to_s
      end
      
      # Lets Authlogic know about the controller object via a before filter, AKA "activates" authlogic.
      module RailsImplementation
        def self.included(klass) # :nodoc:
          if defined?(::ApplicationController)
            raise AuthlogicLoadedTooLateError.new("Authlogic is trying to prepend a before_filter in ActionController::Base to active itself" +
              ", the problem is that ApplicationController has already been loaded meaning the before_filter won't get copied into your" +
              " application. Generally this is due to another gem or plugin requiring your ApplicationController prematurely, such as" +
              " the resource_controller plugin. The solution is to require Authlogic before these other gems / plugins. Please require" +
              " authlogic first to get rid of this error.")
          end
          
          klass.prepend_before_filter :activate_authlogic
        end
        
        private
          def activate_authlogic
            Authlogic::Session::Base.controller = RailsAdapter.new(self)
          end
      end
    end
  end
end

ActionController::Base.send(:include, Authlogic::ControllerAdapters::RailsAdapter::RailsImplementation)
