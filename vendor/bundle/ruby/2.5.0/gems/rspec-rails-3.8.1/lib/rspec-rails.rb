require 'rspec/rails/feature_check'

# Namespace for all core RSpec projects.
module RSpec
  # Namespace for rspec-rails code.
  module Rails
    # Railtie to hook into Rails.
    class Railtie < ::Rails::Railtie
      # As of Rails 5.1.0 you can register directories to work with `rake notes`
      if ::Rails::VERSION::STRING >= '5.1'
        require 'rails/source_annotation_extractor'
        if ::Rails::VERSION::STRING >= '6.0'
          ::Rails::SourceAnnotationExtractor::Annotation.register_directories("spec")
        else
          SourceAnnotationExtractor::Annotation.register_directories("spec")
        end
      end
      # Rails-3.0.1 requires config.app_generators instead of 3.0.0's config.generators
      generators = config.respond_to?(:app_generators) ? config.app_generators : config.generators
      generators.integration_tool :rspec
      generators.test_framework :rspec

      generators do
        ::Rails::Generators.hidden_namespaces.reject! { |namespace| namespace.to_s.start_with?("rspec") }
      end

      rake_tasks do
        load "rspec/rails/tasks/rspec.rake"
      end

      # This is called after the environment has been loaded but before Rails
      # sets the default for the `preview_path`
      initializer "rspec_rails.action_mailer",
                  :before => "action_mailer.set_configs" do |app|
        setup_preview_path(app)
      end

    private

      def setup_preview_path(app)
        return unless supports_action_mailer_previews?(app.config)
        options = app.config.action_mailer
        config_default_preview_path(options) if config_preview_path?(options)
      end

      def config_preview_path?(options)
        # We cannot use `respond_to?(:show_previews)` here as it will always
        # return `true`.
        if ::Rails::VERSION::STRING < '4.2'
          ::Rails.env.development?
        elsif options.show_previews.nil?
          options.show_previews = ::Rails.env.development?
        else
          options.show_previews
        end
      end

      def config_default_preview_path(options)
        return unless options.preview_path.blank?
        options.preview_path = "#{::Rails.root}/spec/mailers/previews"
      end

      def supports_action_mailer_previews?(config)
        # These checks avoid loading `ActionMailer`. Using `defined?` has the
        # side-effect of the class getting loaded if it is available. This is
        # problematic because loading `ActionMailer::Base` will cause it to
        # read the config settings; this is the only time the config is read.
        # If the config is loaded now, any settings declared in a config block
        # in an initializer will be ignored.
        #
        # If the action mailer railtie has not been loaded then `config` will
        # not respond to the method. However, we cannot use
        # `config.action_mailer.respond_to?(:preview_path)` here as it will
        # always return `true`.
        config.respond_to?(:action_mailer) && ::Rails::VERSION::STRING > '4.1'
      end
    end
  end
end
