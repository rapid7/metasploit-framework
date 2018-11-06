module RSpec
  module Rails
    # @private
    module FixtureFileUploadSupport
      delegate :fixture_file_upload, :to => :rails_fixture_file_wrapper

    private

      def rails_fixture_file_wrapper
        RailsFixtureFileWrapper.fixture_path = nil
        resolved_fixture_path = (fixture_path || RSpec.configuration.fixture_path || '').to_s
        RailsFixtureFileWrapper.fixture_path = File.join(resolved_fixture_path, '') unless resolved_fixture_path.strip.empty?
        RailsFixtureFileWrapper.instance
      end

      class RailsFixtureFileWrapper
        include ActionDispatch::TestProcess if defined?(ActionDispatch::TestProcess)

        class << self
          attr_reader :fixture_path

          # Get instance of wrapper
          def instance
            @instance ||= new
          end

          # Override fixture_path set
          # to support Rails 3.0->3.1 using ActionController::TestCase class to resolve fixture_path
          # see https://apidock.com/rails/v3.0.0/ActionDispatch/TestProcess/fixture_file_upload
          def fixture_path=(value)
            if ActionController::TestCase.respond_to?(:fixture_path)
              ActionController::TestCase.fixture_path = value
            end
            @fixture_path = value
          end
        end
      end
    end
  end
end
