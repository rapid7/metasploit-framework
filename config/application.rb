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

      config.paths['log']             = "#{Msf::Config.log_directory}/#{Rails.env}.log"
      config.paths['config/database'] = [Metasploit::Framework::Database.configurations_pathname.try(:to_path)]
      config.autoloader = :zeitwerk

      # Load the Rails 7.1 defaults.
      config.load_defaults 7.1

      # The cache behavior changed with Rails 7.1, and requires the desired version to be set.
      config.active_support.cache_format_version = 7.1

      # The default column serializer was YAML prior to Rails 7.1
      config.active_record.default_column_serializer = ::YAML if config.respond_to?(:active_record) # might not be loaded

      case Rails.env
      when "development"
        config.eager_load = false
      when "test"
        config.eager_load = false
        # Disable file reloading in test
        config.enable_reloading = false
      when "production"
        config.eager_load = false
      end
    end
  end
end

# Silence warnings about this defaulting to true
I18n.enforce_available_locales = true
require 'msfenv'
