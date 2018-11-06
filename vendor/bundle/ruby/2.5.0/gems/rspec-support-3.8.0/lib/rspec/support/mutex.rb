module RSpec
  module Support
    # On 1.8.7, it's in the stdlib.
    # We don't want to load the stdlib, b/c this is a test tool, and can affect
    # the test environment, causing tests to pass where they should fail.
    #
    # So we're transcribing/modifying it from
    # https://github.com/ruby/ruby/blob/v1_8_7_374/lib/thread.rb#L56
    # Some methods we don't need are deleted. Anything I don't
    # understand (there's quite a bit, actually) is left in.
    #
    # Some formating changes are made to appease the robot overlord:
    #   https://travis-ci.org/rspec/rspec-core/jobs/54410874
    # @private
    class Mutex
      def initialize
        @waiting = []
        @locked = false
        @waiting.taint
        taint
      end

      # @private
      def lock
        while Thread.critical = true && @locked
          @waiting.push Thread.current
          Thread.stop
        end
        @locked = true
        Thread.critical = false
        self
      end

      # @private
      def unlock
        return unless @locked
        Thread.critical = true
        @locked = false
        wakeup_and_run_waiting_thread
        self
      end

      # @private
      def synchronize
        lock
        begin
          yield
        ensure
          unlock
        end
      end

    private

      def wakeup_and_run_waiting_thread
        begin
          t = @waiting.shift
          t.wakeup if t
        rescue ThreadError
          retry
        end
        Thread.critical = false
        begin
          t.run if t
        rescue ThreadError
          :noop
        end
      end

      # Avoid warnings for library wide checks spec
    end unless defined?(::RSpec::Support::Mutex) || defined?(::Mutex)
  end
end
