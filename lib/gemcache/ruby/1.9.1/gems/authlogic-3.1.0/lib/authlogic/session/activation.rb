module Authlogic
  module Session
    # Activating Authlogic requires that you pass it an Authlogic::ControllerAdapters::AbstractAdapter object, or a class that extends it.
    # This is sort of like a database connection for an ORM library, Authlogic can't do anything until it is "connected" to a controller.
    # If you are using a supported framework, Authlogic takes care of this for you.
    module Activation
      class NotActivatedError < ::StandardError # :nodoc:
        def initialize(session)
          super("You must activate the Authlogic::Session::Base.controller with a controller object before creating objects")
        end
      end
      
      def self.included(klass)
        klass.class_eval do
          extend ClassMethods
          include InstanceMethods
        end
      end
      
      module ClassMethods
        # Returns true if a controller has been set and can be used properly. This MUST be set before anything can be done.
        # Similar to how ActiveRecord won't allow you to do anything without establishing a DB connection. In your framework
        # environment this is done for you, but if you are using Authlogic outside of your framework, you need to assign a controller
        # object to Authlogic via Authlogic::Session::Base.controller = obj. See the controller= method for more information.
        def activated?
          !controller.nil?
        end
        
        # This accepts a controller object wrapped with the Authlogic controller adapter. The controller adapters close the gap
        # between the different controllers in each framework. That being said, Authlogic is expecting your object's class to
        # extend Authlogic::ControllerAdapters::AbstractAdapter. See Authlogic::ControllerAdapters for more info.
        #
        # Lastly, this is thread safe.
        def controller=(value)
          Thread.current[:authlogic_controller] = value
        end
        
        # The current controller object
        def controller
          Thread.current[:authlogic_controller]
        end
      end
      
      module InstanceMethods
        # Making sure we are activated before we start creating objects
        def initialize(*args)
          raise NotActivatedError.new(self) unless self.class.activated?
          super
        end
        
        private
          def controller
            self.class.controller
          end
      end
    end
  end
end