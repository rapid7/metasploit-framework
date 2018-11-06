require 'rspec/mocks'

module RSpec
  module Core
    module MockingAdapters
      # @private
      module RSpec
        include ::RSpec::Mocks::ExampleMethods

        def self.framework_name
          :rspec
        end

        def self.configuration
          ::RSpec::Mocks.configuration
        end

        def setup_mocks_for_rspec
          ::RSpec::Mocks.setup
        end

        def verify_mocks_for_rspec
          ::RSpec::Mocks.verify
        end

        def teardown_mocks_for_rspec
          ::RSpec::Mocks.teardown
        end
      end
    end
  end
end
