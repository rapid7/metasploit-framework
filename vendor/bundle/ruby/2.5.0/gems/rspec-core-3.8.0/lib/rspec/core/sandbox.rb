module RSpec
  module Core
    # A sandbox isolates the enclosed code into an environment that looks 'new'
    # meaning globally accessed objects are reset for the duration of the
    # sandbox.
    #
    # @note This module is not normally available. You must require
    #   `rspec/core/sandbox` to load it.
    module Sandbox
      # Execute a provided block with RSpec global objects (configuration,
      # world) reset.  This is used to test RSpec with RSpec.
      #
      # When calling this the configuration is passed into the provided block.
      # Use this to set custom configs for your sandboxed examples.
      #
      # ```
      # Sandbox.sandboxed do |config|
      #   config.before(:context) { RSpec.current_example = nil }
      # end
      # ```
      def self.sandboxed
        orig_config  = RSpec.configuration
        orig_world   = RSpec.world
        orig_example = RSpec.current_example

        RSpec.configuration = RSpec::Core::Configuration.new
        RSpec.world         = RSpec::Core::World.new(RSpec.configuration)

        yield RSpec.configuration
      ensure
        RSpec.configuration   = orig_config
        RSpec.world           = orig_world
        RSpec.current_example = orig_example
      end
    end
  end
end
