module Authlogic
  module ControllerAdapters # :nodoc:
    # Allows you to use Authlogic in any framework you want, not just rails. See the RailsAdapter or MerbAdapter
    # for an example of how to adapt Authlogic to work with your framework.
    class AbstractAdapter
      attr_accessor :controller

      def initialize(controller)
        self.controller = controller
      end
      
      def authenticate_with_http_basic(&block)
        @auth = Rack::Auth::Basic::Request.new(controller.request.env)
        if @auth.provided? and @auth.basic?
          block.call(*@auth.credentials)
        else
          false
        end
      end
      
      def cookies
        controller.cookies
      end
      
      def cookie_domain
        raise NotImplementedError.new("The cookie_domain method has not been implemented by the controller adapter")
      end

      def params
        controller.params
      end

      def request
        controller.request
      end

      def request_content_type
        request.content_type
      end

      def session
        controller.session
      end
      
      def responds_to_single_access_allowed?
        controller.respond_to?(:single_access_allowed?, true)
      end
      
      def single_access_allowed?
        controller.send(:single_access_allowed?)
      end
      
      def responds_to_last_request_update_allowed?
        controller.respond_to?(:last_request_update_allowed?, true)
      end
      
      def last_request_update_allowed?
        controller.send(:last_request_update_allowed?)
      end
      
      private
        def method_missing(id, *args, &block)
          controller.send(id, *args, &block)
        end
    end
  end
end