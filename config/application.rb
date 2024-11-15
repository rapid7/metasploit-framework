require 'fiddle'
Fiddle.const_set(:VERSION, '0.0.0') unless Fiddle.const_defined?(:VERSION)

require 'rails'
require File.expand_path('../boot', __FILE__)

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

      config.paths['log'] = "#{Msf::Config.log_directory}/#{Rails.env}.log"
      config.paths['config/database'] = [Metasploit::Framework::Database.configurations_pathname.try(:to_path)]

      config.autoloader = :zeitwerk

      # Load the Rails 7.1 defaults.
      config.load_defaults 7.1

      # The cache behavior changed with Rails 7.1, and requires the desired version to be set.
      config.active_support.cache_format_version = 7.1

      # Timezone shenanigans
      config.time_zone = 'UTC'

      if config.respond_to?(:active_record)
        # The default column serializer was YAML prior to Rails 7.1
        config.active_record.default_column_serializer = ::YAML

        # Timezone settings
        config.active_record.default_timezone = :local

        # Partials inserts are disabled by default in Rails 7
        # This only writes attributes that changed.
        config.active_record.partial_inserts = true

        # Foreign Key Validation - Belongs-to
        # Was not enabled by default
        config.active_record.belongs_to_required_validates_foreign_key = true

        # This behavior changed in 7.1
        config.active_record.commit_transaction_on_non_local_return = false

        # Originally allowed but silently ignored, raises in 7.1
        config.active_record.raise_on_assign_to_attr_readonly = false

        # Rails originally ran the callbacks on the first commit change.
        # In Rails 7.1 this is done on all models, so we need to retain the behavior for now.
        config.active_record.run_commit_callbacks_on_first_saved_instances_in_transaction = true

        # Rails 7.1 will execute after commit callbacks in order they are defined.
        # Originally it was in reverse order.
        config.active_record.run_after_transaction_callbacks_in_order_defined = false
      end

      # We never eager load files.
      config.eager_load = false
      config.enable_reloading = ::Rails.env.test?
    end
  end
end

# Silence warnings about this defaulting to true
I18n.enforce_available_locales = true
require 'msfenv'
