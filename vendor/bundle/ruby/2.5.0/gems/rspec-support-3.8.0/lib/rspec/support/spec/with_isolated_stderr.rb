module RSpec
  module Support
    module WithIsolatedStdErr
      def with_isolated_stderr
        original = $stderr
        $stderr = StringIO.new
        yield
      ensure
        $stderr = original
      end
    end
  end
end
