module Authlogic
  module ControllerAdapters
    # Adapts authlogic to work with merb. The point is to close the gap between what authlogic expects and what the merb controller object
    # provides. Similar to how ActiveRecord has an adapter for MySQL, PostgreSQL, SQLite, etc.
    class MerbAdapter < AbstractAdapter
      # Lets Authlogic know about the controller object via a before filter, AKA "activates" authlogic.
      module MerbImplementation
        def self.included(klass) # :nodoc:
          klass.before :activate_authlogic
        end
        
        def cookie_domain
          Merb::Config[:session_cookie_domain]
        end

        private
          def activate_authlogic
            Authlogic::Session::Base.controller = MerbAdapter.new(self)
          end
      end
    end
  end
end
 
# make sure we're running inside Merb
if defined?(Merb::Plugins)
  Merb::BootLoader.before_app_loads do
    Merb::Controller.send(:include, Authlogic::ControllerAdapters::MerbAdapter::MerbImplementation)
  end
end