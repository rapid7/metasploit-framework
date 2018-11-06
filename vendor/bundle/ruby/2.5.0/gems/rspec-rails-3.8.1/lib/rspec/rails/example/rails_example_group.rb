# Temporary workaround to resolve circular dependency between rspec-rails' spec
# suite and ammeter.
require 'rspec/rails/matchers'

module RSpec
  module Rails
    # @api public
    # Common rails example functionality.
    module RailsExampleGroup
      extend ActiveSupport::Concern
      include RSpec::Rails::SetupAndTeardownAdapter
      include RSpec::Rails::MinitestLifecycleAdapter if ::Rails::VERSION::STRING >= '4'
      include RSpec::Rails::MinitestAssertionAdapter
      include RSpec::Rails::FixtureSupport
    end
  end
end
