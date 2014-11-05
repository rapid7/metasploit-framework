module Metasploit::Framework::Spec::Threads::Suite
  #
  # CONSTANTS
  #

  EXPECTED_THREAD_COUNT_BEFORE_SUITE = 1

  #
  # Module Methods
  #

  # Configures `before(:suite)` and `after(:suite)` callback to detect thread leaks.
  #
  # @return [void]
  def self.configure!
    unless @configured
      RSpec.configure do |config|
        config.before(:suite) do
          thread_count = Thread.list.count

          expect(thread_count).to(
              (be <= EXPECTED_THREAD_COUNT_BEFORE_SUITE),
              "#{thread_count} #{'thread'.pluralize(thread_count)} exist(s) when " \
              "only #{EXPECTED_THREAD_COUNT_BEFORE_SUITE} #{'thread'.pluralize(EXPECTED_THREAD_COUNT_BEFORE_SUITE)} " \
              "expected before suite runs"
          )
        end
      end

      @configured = true
    end

    @configured
  end
end