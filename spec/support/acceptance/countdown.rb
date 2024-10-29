module Acceptance
  ###
  # A utility class which can be used in conjunction with Timeout mechanisms
  ###
  class Countdown
    # @param [int] timeout The time in seconds that this count starts from
    def initialize(timeout)
      @start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC, :second)
      @end_time = @start_time + timeout
      @timeout = timeout
    end

    # @return [TrueClass, FalseClass] True if the timeout has surpassed, false otherwise
    def elapsed?
      remaining_time == 0
    end

    # @return [Integer] The time in seconds left before this countdown expires
    def remaining_time
      [@end_time - Process.clock_gettime(Process::CLOCK_MONOTONIC, :second), 0].max
    end
  end
end
