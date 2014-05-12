require 'rails'
require File.expand_path('../boot', __FILE__)

# only the parts of 'rails/all' that metasploit-framework actually uses
require 'active_record/railtie'

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

require 'msf/base/config'

module Metasploit
  module Framework
    class Application < Rails::Application
      user_config_root = Pathname.new(Msf::Config.get_config_root)
      user_database_yaml = user_config_root.join('database.yml')

      if user_database_yaml.exist?
        config.paths['config/database'] = [user_database_yaml.to_path]
      end
    end
  end
end