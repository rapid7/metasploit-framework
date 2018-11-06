module RSpec
  module Mocks
    module Matchers
      # @private
      class ExpectationCustomization
        attr_accessor :block

        def initialize(method_name, args, block)
          @method_name = method_name
          @args        = args
          @block       = block
        end

        def playback_onto(expectation)
          expectation.__send__(@method_name, *@args, &@block)
        end
      end
    end
  end
end
