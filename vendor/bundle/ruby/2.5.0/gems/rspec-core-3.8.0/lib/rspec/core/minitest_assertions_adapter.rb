begin
  # Only the minitest 5.x gem includes the minitest.rb and assertions.rb files.
  require 'minitest'
  require 'minitest/assertions'
rescue LoadError
  # We must be using Ruby Core's MiniTest or the Minitest gem 4.x.
  require 'minitest/unit'
  Minitest = MiniTest
end

module RSpec
  module Core
    # @private
    module MinitestAssertionsAdapter
      include ::Minitest::Assertions
      # Need to forcefully include Pending after Minitest::Assertions
      # to make sure our own #skip method beats Minitest's.
      include ::RSpec::Core::Pending

      # Minitest 5.x requires this accessor to be available. See
      # https://github.com/seattlerb/minitest/blob/38f0a5fcbd9c37c3f80a3eaad4ba84d3fc9947a0/lib/minitest/assertions.rb#L8
      #
      # It is not required for other extension libraries, and RSpec does not
      # report or make this information available to formatters.
      attr_writer :assertions
      def assertions
        @assertions ||= 0
      end
    end
  end
end
