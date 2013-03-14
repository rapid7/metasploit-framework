module Authlogic
  module TestCase
    # Simple class to replace real loggers, so that we can raise any errors being logged.
    class MockLogger
      def error(message)
        raise message
      end
    end
  end
end