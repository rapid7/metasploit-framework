module Authlogic
  module TestCase
    class MockRequest # :nodoc:
      attr_accessor :controller
      
      def initialize(controller)
        self.controller = controller
      end
      
      def remote_ip
        (controller && controller.respond_to?(:env) && controller.env.is_a?(Hash) && controller.env['REMOTE_ADDR']) || "1.1.1.1"
      end
      
      private
        def method_missing(*args, &block)
        end
    end
  end
end