# frozen_string_literal: true

module Msf::MCP
  module Security
    class RateLimiter
      #attr_reader :requests_per_minute, :burst_size

      # Initialize rate limiter with token bucket algorithm
      #
      # @param requests_per_minute [Integer] Maximum requests per minute
      # @param burst_size [Integer] Maximum burst size (default: same as requests_per_minute)
      def initialize(requests_per_minute: 60, burst_size: nil)
        @requests_per_minute = requests_per_minute
        @burst_size = burst_size || requests_per_minute
        @tokens = @burst_size.to_f
        @last_refill = Time.now
        @mutex = Mutex.new
      end

      # Check if request is allowed, consume token if yes
      #
      # @param tool_name [String, nil] Tool name (for logging/tracking)
      # @return [Integer] Number of tokens,if request allowed
      # @raise [RateLimitExceededError] If rate limit exceeded
      def check_rate_limit!(tool_name = nil)
        @mutex.synchronize do
          refill!

          if @tokens >= 1.0
            @tokens -= 1.0
          else
            # Calculate retry_after in seconds
            tokens_per_second = @requests_per_minute / 60.0
            retry_after = ((1.0 - @tokens) / tokens_per_second).ceil

            raise RateLimitExceededError.new(retry_after)
          end
        end
      end

      private

      # Refill tokens based on elapsed time
      def refill!
        now = Time.now
        elapsed = now - @last_refill

        # Calculate tokens to add based on elapsed time
        tokens_per_second = @requests_per_minute / 60.0
        tokens_to_add = elapsed * tokens_per_second

        # Add tokens but cap at burst_size
        @tokens = [@tokens + tokens_to_add, @burst_size.to_f].min
        @last_refill = now
      end
    end
  end
end
