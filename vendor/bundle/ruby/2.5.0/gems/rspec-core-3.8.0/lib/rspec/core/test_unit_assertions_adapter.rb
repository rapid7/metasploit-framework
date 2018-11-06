require 'test/unit/assertions'

module RSpec
  module Core
    # @private
    module TestUnitAssertionsAdapter
      include ::Test::Unit::Assertions

      # If using test/unit from Ruby core with Ruby 1.9+, it includes
      # MiniTest::Assertions by default. Note the upcasing of 'Test'.
      #
      # If the test/unit gem is being loaded, it will not include any minitest
      # assertions.
      #
      # Only if Minitest 5.x is included / loaded do we need to worry about
      # adding a shim for the new updates. Thus instead of checking on the
      # RUBY_VERSION we need to check ancestors.
      begin
        # MiniTest is 4.x.
        # Minitest is 5.x.
        if ancestors.include?(::Minitest::Assertions)
          require 'rspec/core/minitest_assertions_adapter'
          include ::RSpec::Core::MinitestAssertionsAdapter
        end
      rescue NameError
        # No-op. Minitest 5.x was not loaded.
      end
    end
  end
end
