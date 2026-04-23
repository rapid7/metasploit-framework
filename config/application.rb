require 'fiddle'
Fiddle.const_set(:VERSION, '0.0.0') unless Fiddle.const_defined?(:VERSION)

require 'rails'
require File.expand_path('../boot', __FILE__)

require 'action_view'
# Monkey patch for ActionView::Helpers::TagHelper::TagBuilder.define_element
#
# Metasploit's global Kernel patch (lib/rex.rb) overrides Kernel#select and Kernel#sleep.
# ActionView's define_element checks whether a method already exists before defining HTML
# element helpers (e.g. :select). Because Kernel#select is in the ancestor chain, the check
# returns true and the :select element helper is never defined, breaking tag.select().
#
# Rails 7.2.x uses `instance_methods.include?(method_name.to_sym)` — affected.
# Rails 8.0.x uses `return if method_defined?(name)` — also affected, since method_defined?
# checks the ancestor chain including Kernel.
#
# See: https://github.com/rapid7/metasploit-framework/blob/ae1db09f32cd04c007dbf445cf16dc22c9fc2e53/lib/rex.rb#L74-L79
if ActionView::VERSION::MAJOR == 8
  # Rails 8.0.x patch: override define_element to skip the method_defined? guard
  # https://github.com/rails/rails/blob/v8.0.5/actionview/lib/action_view/helpers/tag_helper.rb#L51
  module ActionView::Helpers::TagHelper
    class TagBuilder
      def self.define_element(name, code_generator:, method_name: name)
        code_generator.class_eval do |batch|
          batch << "\n" <<
            "def #{method_name}(content = nil, escape: true, **options, &block)" <<
            "  tag_string(#{name.inspect}, content, options, escape: escape, &block)" <<
            "end"
        end
      end
    end
  end
end

all_environments = [
    :development,
    :production,
    :test
]

Bundler.require(
    *Rails.groups(
        coverage: [:test],
        db: all_environments,
        pcap: all_environments
    )
)

#
# Railties
#

# For compatibility with jquery-rails (and other engines that need action_view) in pro
require 'action_controller/railtie'
require 'action_view/railtie'

#
# Project
#

require 'metasploit/framework/common_engine'
require 'metasploit/framework/database'
module Metasploit
  module Framework
    class Application < Rails::Application
      include Metasploit::Framework::CommonEngine

      config.paths['log']             = "#{Msf::Config.log_directory}/#{Rails.env}.log"
      config.paths['config/database'] = [Metasploit::Framework::Database.configurations_pathname.try(:to_path)]

      # Rails 8.0 upgrade: changed from 'config.load_defaults 7.2'.
      # Activates Rails 8.0 framework defaults including:
      #   - config.active_support.to_time_preserves_timezone = :zone
      #   - config.active_record.default_column_serializer = nil
      #   - config.active_record.run_after_transaction_callbacks_in_order_defined = true
      # The config.autoloader = :zeitwerk line was also removed here because
      # Zeitwerk is the only autoloader in Rails 8 — the setting no longer exists.
      config.load_defaults 8.0

      config.eager_load = false
    end
  end
end

# Silence warnings about this defaulting to true
I18n.enforce_available_locales = true
require 'msfenv'
