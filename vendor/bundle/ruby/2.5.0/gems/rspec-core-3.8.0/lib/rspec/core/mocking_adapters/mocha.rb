# In order to support all versions of mocha, we have to jump through some
# hoops here.
#
# mocha >= '0.13.0':
#   require 'mocha/api' is required.
#   require 'mocha/object' raises a LoadError b/c the file no longer exists.
# mocha < '0.13.0', >= '0.9.7'
#   require 'mocha/api' is required.
#   require 'mocha/object' is required.
# mocha < '0.9.7':
#   require 'mocha/api' raises a LoadError b/c the file does not yet exist.
#   require 'mocha/standalone' is required.
#   require 'mocha/object' is required.
begin
  require 'mocha/api'

  begin
    require 'mocha/object'
  rescue LoadError
    # Mocha >= 0.13.0 no longer contains this file nor needs it to be loaded.
  end
rescue LoadError
  require 'mocha/standalone'
  require 'mocha/object'
end

module RSpec
  module Core
    module MockingAdapters
      # @private
      module Mocha
        def self.framework_name
          :mocha
        end

        # Mocha::Standalone was deprecated as of Mocha 0.9.7.
        begin
          include ::Mocha::API
        rescue NameError
          include ::Mocha::Standalone
        end

        def setup_mocks_for_rspec
          mocha_setup
        end

        def verify_mocks_for_rspec
          mocha_verify
        end

        def teardown_mocks_for_rspec
          mocha_teardown
        end
      end
    end
  end
end
