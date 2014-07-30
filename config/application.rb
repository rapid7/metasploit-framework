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
# Project
#

require 'metasploit/framework/common_engine'
require 'msf/base/config'

module Metasploit
  module Framework
    class Application < Rails::Application
      include Metasploit::Framework::CommonEngine

      user_config_root = Pathname.new(Msf::Config.get_config_root)
      user_database_yaml = user_config_root.join('database.yml')

      if user_database_yaml.exist?
        config.paths['config/database'] = [user_database_yaml.to_path]
      end
    end
  end
end

# Silence warnings about this defaulting to true
I18n.enforce_available_locales = true
