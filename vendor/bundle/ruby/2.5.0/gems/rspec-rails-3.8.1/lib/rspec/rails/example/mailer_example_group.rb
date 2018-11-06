module RSpec
  module Rails
    # @api public
    # Container module for mailer spec functionality. It is only available if
    # ActionMailer has been loaded before it.
    module MailerExampleGroup
      # This blank module is only necessary for YARD processing. It doesn't
      # handle the conditional `defined?` check below very well.
    end
  end
end

if defined?(ActionMailer)
  module RSpec
    module Rails
      # Container module for mailer spec functionality.
      module MailerExampleGroup
        extend ActiveSupport::Concern
        include RSpec::Rails::RailsExampleGroup
        include ActionMailer::TestCase::Behavior

        included do
          include ::Rails.application.routes.url_helpers
          options = ::Rails.configuration.action_mailer.default_url_options
          options.each { |key, value| default_url_options[key] = value } if options
        end

        # Class-level DSL for mailer specs.
        module ClassMethods
          # Alias for `described_class`.
          def mailer_class
            described_class
          end
        end
      end
    end
  end
end
