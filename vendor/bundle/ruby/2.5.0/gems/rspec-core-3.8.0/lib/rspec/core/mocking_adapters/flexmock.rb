#  Created by Jim Weirich on 2007-04-10.
#  Copyright (c) 2007. All rights reserved.

require 'flexmock/rspec'

module RSpec
  module Core
    module MockingAdapters
      # @private
      module Flexmock
        include ::FlexMock::MockContainer

        def self.framework_name
          :flexmock
        end

        def setup_mocks_for_rspec
          # No setup required.
        end

        def verify_mocks_for_rspec
          flexmock_verify
        end

        def teardown_mocks_for_rspec
          flexmock_close
        end
      end
    end
  end
end
