module RSpec
  module Core
    module MockingAdapters
      # @private
      module Null
        def setup_mocks_for_rspec; end

        def verify_mocks_for_rspec; end

        def teardown_mocks_for_rspec; end
      end
    end
  end
end
