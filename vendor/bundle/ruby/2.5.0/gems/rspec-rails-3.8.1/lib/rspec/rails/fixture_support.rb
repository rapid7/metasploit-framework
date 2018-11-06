module RSpec
  module Rails
    # @private
    module FixtureSupport
      if defined?(ActiveRecord::TestFixtures)
        extend ActiveSupport::Concern
        include RSpec::Rails::SetupAndTeardownAdapter
        include RSpec::Rails::MinitestLifecycleAdapter if ::ActiveRecord::VERSION::STRING > '4'
        include RSpec::Rails::MinitestAssertionAdapter
        include ActiveRecord::TestFixtures

        included do
          # TODO: (DC 2011-06-25) this is necessary because fixture_file_upload
          # accesses fixture_path directly on ActiveSupport::TestCase. This is
          # fixed in rails by https://github.com/rails/rails/pull/1861, which
          # should be part of the 3.1 release, at which point we can include
          # these lines for rails < 3.1.
          ActiveSupport::TestCase.class_exec do
            include ActiveRecord::TestFixtures
            self.fixture_path = RSpec.configuration.fixture_path
          end
          # /TODO

          self.fixture_path = RSpec.configuration.fixture_path
          if ::Rails::VERSION::STRING > '5'
            self.use_transactional_tests = RSpec.configuration.use_transactional_fixtures
          else
            self.use_transactional_fixtures = RSpec.configuration.use_transactional_fixtures
          end
          self.use_instantiated_fixtures  = RSpec.configuration.use_instantiated_fixtures

          def self.fixtures(*args)
            orig_methods = private_instance_methods
            super.tap do
              new_methods = private_instance_methods - orig_methods
              new_methods.each do |method_name|
                proxy_method_warning_if_called_in_before_context_scope(method_name)
              end
            end
          end

          def self.proxy_method_warning_if_called_in_before_context_scope(method_name)
            orig_implementation = instance_method(method_name)
            define_method(method_name) do |*args, &blk|
              if inspect.include?("before(:context)")
                RSpec.warn_with("Calling fixture method in before :context ")
              else
                orig_implementation.bind(self).call(*args, &blk)
              end
            end
          end

          fixtures RSpec.configuration.global_fixtures if RSpec.configuration.global_fixtures
        end
      end
    end
  end
end
