require 'rails'
require File.expand_path('../boot', __FILE__)

all_environments = [
    :development,
    :production,
    :test
]

Bundler.require(
    *Rails.groups(
        db: all_environments,
        pcap: all_environments
    )
)

#
# Railties
#

# For compatibility with jquery-rails (and other engines that need action_view) in pro
require 'action_view/railtie'

#
# Project
#

require 'metasploit/framework/common_engine'
require 'msf/base/config'

module Metasploit
  module Framework
    class Application < Rails::Application
      include Metasploit::Framework::CommonEngine

      environment_database_yaml = ENV['MSF_DATABASE_CONFIG']

      if environment_database_yaml
        # DO NOT check if the path exists: if the environment variable is set, then the user meant to use this path
        # and if it doesn't exist then an error should occur so the user knows the environment variable points to a
        # non-existent file.
        config.paths['config/database'] = environment_database_yaml
      else
        user_config_root = Pathname.new(Msf::Config.get_config_root)
        user_database_yaml = user_config_root.join('database.yml')

        # DO check if the path exists as in test environments there may be no config root, in which case the normal
        # rails location, `config/database.yml`, should contain the database config.
        if user_database_yaml.exist?
          config.paths['config/database'] = [user_database_yaml.to_path]
        end
      end
    end
  end
end

# Silence warnings about this defaulting to true
I18n.enforce_available_locales = true
