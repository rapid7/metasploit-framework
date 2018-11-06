require "rails/deprecated_sanitizer/version"
require "rails/deprecated_sanitizer/html-scanner"
require "rails/deprecated_sanitizer/railtie" if defined?(Rails::Railtie)
require "active_support/core_ext/module/remove_method"

module Rails
  module DeprecatedSanitizer
    extend self

    def full_sanitizer
      HTML::FullSanitizer
    end

    def link_sanitizer
      HTML::LinkSanitizer
    end

    def white_list_sanitizer
      HTML::WhiteListSanitizer
    end
  end
end

module ActionView
  module Helpers
    module SanitizeHelper
      module ClassMethods
        redefine_method :sanitizer_vendor do
          Rails::DeprecatedSanitizer
        end

        redefine_method :sanitized_protocol_separator do
          white_list_sanitizer.protocol_separator
        end

        redefine_method :sanitized_uri_attributes do
          white_list_sanitizer.uri_attributes
        end

        redefine_method :sanitized_bad_tags do
          white_list_sanitizer.bad_tags
        end

        redefine_method :sanitized_allowed_css_properties do
          white_list_sanitizer.allowed_css_properties
        end

        redefine_method :sanitized_allowed_css_keywords do
          white_list_sanitizer.allowed_css_keywords
        end

        redefine_method :sanitized_shorthand_css_properties do
          white_list_sanitizer.shorthand_css_properties
        end

        redefine_method :sanitized_allowed_protocols do
          white_list_sanitizer.allowed_protocols
        end

        redefine_method :sanitized_protocol_separator= do |value|
          white_list_sanitizer.protocol_separator = value
        end

        # Adds valid HTML attributes that the +sanitize+ helper checks for URIs.
        #
        #   class Application < Rails::Application
        #     config.action_view.sanitized_uri_attributes = 'lowsrc', 'target'
        #   end
        #
        redefine_method :sanitized_uri_attributes= do |attributes|
          HTML::WhiteListSanitizer.uri_attributes.merge(attributes)
        end

        # Adds to the Set of 'bad' tags for the +sanitize+ helper.
        #
        #   class Application < Rails::Application
        #     config.action_view.sanitized_bad_tags = 'embed', 'object'
        #   end
        #
        redefine_method :sanitized_bad_tags= do |attributes|
          HTML::WhiteListSanitizer.bad_tags.merge(attributes)
        end

        # Adds to the Set of allowed tags for the +sanitize+ helper.
        #
        #   class Application < Rails::Application
        #     config.action_view.sanitized_allowed_tags = 'table', 'tr', 'td'
        #   end
        #
        redefine_method :sanitized_allowed_tags= do |attributes|
          HTML::WhiteListSanitizer.allowed_tags.merge(attributes)
        end

        # Adds to the Set of allowed HTML attributes for the +sanitize+ helper.
        #
        #   class Application < Rails::Application
        #     config.action_view.sanitized_allowed_attributes = ['onclick', 'longdesc']
        #   end
        #
        redefine_method :sanitized_allowed_attributes= do |attributes|
          HTML::WhiteListSanitizer.allowed_attributes.merge(attributes)
        end

        # Adds to the Set of allowed CSS properties for the #sanitize and +sanitize_css+ helpers.
        #
        #   class Application < Rails::Application
        #     config.action_view.sanitized_allowed_css_properties = 'expression'
        #   end
        #
        redefine_method :sanitized_allowed_css_properties= do |attributes|
          HTML::WhiteListSanitizer.allowed_css_properties.merge(attributes)
        end

        # Adds to the Set of allowed CSS keywords for the +sanitize+ and +sanitize_css+ helpers.
        #
        #   class Application < Rails::Application
        #     config.action_view.sanitized_allowed_css_keywords = 'expression'
        #   end
        #
        redefine_method :sanitized_allowed_css_keywords= do |attributes|
          HTML::WhiteListSanitizer.allowed_css_keywords.merge(attributes)
        end

        # Adds to the Set of allowed shorthand CSS properties for the +sanitize+ and +sanitize_css+ helpers.
        #
        #   class Application < Rails::Application
        #     config.action_view.sanitized_shorthand_css_properties = 'expression'
        #   end
        #
        redefine_method :sanitized_shorthand_css_properties= do |attributes|
          HTML::WhiteListSanitizer.shorthand_css_properties.merge(attributes)
        end

        # Adds to the Set of allowed protocols for the +sanitize+ helper.
        #
        #   class Application < Rails::Application
        #     config.action_view.sanitized_allowed_protocols = 'ssh', 'feed'
        #   end
        #
        redefine_method :sanitized_allowed_protocols= do |attributes|
          HTML::WhiteListSanitizer.allowed_protocols.merge(attributes)
        end
      end
    end
  end
end
