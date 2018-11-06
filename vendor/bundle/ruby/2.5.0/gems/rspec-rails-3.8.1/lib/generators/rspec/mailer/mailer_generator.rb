require 'generators/rspec'
require "rspec/rails/feature_check"

module Rspec
  module Generators
    # @private
    class MailerGenerator < Base
      argument :actions, :type => :array, :default => [], :banner => "method method"

      def generate_mailer_spec
        template "mailer_spec.rb", File.join('spec/mailers', class_path, "#{file_name}_spec.rb")
      end

      def generate_fixtures_files
        actions.each do |action|
          @action, @path = action, File.join(file_path, action)
          template "fixture", File.join("spec/fixtures", @path)
        end
      end

      def generate_preview_files
        return unless RSpec::Rails::FeatureCheck.has_action_mailer_preview?
        template "preview.rb", File.join("spec/mailers/previews", class_path, "#{file_name}_preview.rb")
      end
    end
  end
end
