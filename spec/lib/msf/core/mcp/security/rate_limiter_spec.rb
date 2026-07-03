# frozen_string_literal: true

require 'msf/core/mcp'

RSpec.describe Msf::MCP::Security::RateLimiter do
  describe '#initialize' do
    it 'sets requests_per_minute' do
      limiter = described_class.new(requests_per_minute: 30)
      expect(limiter.instance_variable_get(:@requests_per_minute)).to eq(30)
    end

    it 'sets burst_size to requests_per_minute by default' do
      limiter = described_class.new(requests_per_minute: 30)
      expect(limiter.instance_variable_get(:@burst_size)).to eq(30)
    end

    it 'allows custom burst_size' do
      limiter = described_class.new(requests_per_minute: 30, burst_size: 50)
      expect(limiter.instance_variable_get(:@burst_size)).to eq(50)
    end

    it 'initializes with full token bucket' do
      limiter = described_class.new(requests_per_minute: 60)
      expect(limiter.instance_variable_get(:@tokens)).to eq(60.0)
    end
  end

  describe '#check_rate_limit!' do
    let(:limiter) { described_class.new(requests_per_minute: 60) }

    it 'allows request when tokens available' do
      expect { limiter.check_rate_limit! }.not_to raise_error
    end

    it 'consumes one token per request' do
      initial_tokens = limiter.instance_variable_get(:@tokens)
      new_tokens = limiter.check_rate_limit!
      expect(new_tokens).to be < initial_tokens
    end

    it 'allows multiple requests up to burst_size' do
      limiter = described_class.new(requests_per_minute: 10)

      10.times do
        expect { limiter.check_rate_limit! }.not_to raise_error
      end
    end

    it 'raises RateLimitExceededError when tokens exhausted' do
      limiter = described_class.new(requests_per_minute: 2)

      # Consume all tokens
      2.times { limiter.check_rate_limit! }

      # Next request should raise
      expect { limiter.check_rate_limit! }.to raise_error(
        Msf::MCP::Security::RateLimitExceededError
      )
    end

    it 'includes retry_after in error' do
      limiter = described_class.new(requests_per_minute: 60)

      # Exhaust tokens
      60.times { limiter.check_rate_limit! }

      expect { limiter.check_rate_limit! }.to raise_error(Msf::MCP::Security::RateLimitExceededError) do |error|
        expect(error.retry_after).to be_a(Integer)
        expect(error.retry_after).to be > 0
      end
    end

    it 'returns true when successful' do
      tokens = limiter.check_rate_limit!
      expect(tokens).not_to be_nil
    end

    it 'accepts optional tool_name parameter' do
      expect { limiter.check_rate_limit!('test_tool') }.not_to raise_error
    end
  end

  describe 'token refill' do
    it 'adds tokens based on elapsed time' do
      start = Time.now
      allow(Time).to receive(:now).and_return(start)
      limiter = described_class.new(requests_per_minute: 60)

      # Consume all tokens
      60.times { limiter.check_rate_limit! }

      # Advance time by 2 seconds (should refill ~2 tokens at 1/sec)
      allow(Time).to receive(:now).and_return(start + 2)

      # Should allow a request now
      expect { limiter.check_rate_limit! }.not_to raise_error
    end

    it 'caps tokens at burst_size' do
      start = Time.now
      allow(Time).to receive(:now).and_return(start)
      limiter = described_class.new(requests_per_minute: 60, burst_size: 5)

      # Consume 1 token
      limiter.check_rate_limit!

      # Advance time far enough to fully refill
      allow(Time).to receive(:now).and_return(start + 600)

      # Should allow burst_size requests but not burst_size + 1
      5.times { expect { limiter.check_rate_limit! }.not_to raise_error }
      expect { limiter.check_rate_limit! }.to raise_error(Msf::MCP::Security::RateLimitExceededError)
    end

    it 'refills proportionally to time elapsed' do
      start = Time.now
      allow(Time).to receive(:now).and_return(start)
      limiter = described_class.new(requests_per_minute: 60)

      # Exhaust all tokens
      60.times { limiter.check_rate_limit! }

      # Advance by exactly 1 second (should add exactly 1 token at 60/min = 1/sec)
      allow(Time).to receive(:now).and_return(start + 1)

      # Should allow exactly 1 request
      expect { limiter.check_rate_limit! }.not_to raise_error
      expect { limiter.check_rate_limit! }.to raise_error(Msf::MCP::Security::RateLimitExceededError)
    end
  end

  describe 'thread safety' do
    it 'handles concurrent requests correctly' do
      limiter = described_class.new(requests_per_minute: 100)

      # Try to make 100 requests concurrently
      threads = 100.times.map do
        Thread.new do
          limiter.check_rate_limit!
        rescue Msf::MCP::Security::RateLimitExceededError
          # Some may be rate limited, that's ok
          nil
        end
      end

      threads.each(&:join)

      # All tokens should be consumed
      expect(limiter.instance_variable_get(:@tokens)).to be < 1.0
    end

    it 'does not allow more requests than burst_size concurrently' do
      limiter = described_class.new(requests_per_minute: 10)

      success_count = 0
      mutex = Mutex.new
      threads = 20.times.map do
        Thread.new do
          limiter.check_rate_limit!
          mutex.synchronize { success_count += 1 }
        rescue Msf::MCP::Security::RateLimitExceededError
          # Expected for requests beyond burst_size
        end
      end

      threads.each(&:join)

      # Should have exactly 10 successful requests
      expect(success_count).to eq(10)
    end
  end
end

RSpec.describe Msf::MCP::Security::RateLimitExceededError do
  describe '#initialize' do
    it 'sets retry_after' do
      error = described_class.new(5)
      expect(error.retry_after).to eq(5)
    end

    it 'sets error message' do
      error = described_class.new(5)
      expect(error.message).to include('Rate limit exceeded')
      expect(error.message).to include('5 seconds')
    end
  end
end
