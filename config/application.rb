require 'rails'
require File.expand_path('../boot', __FILE__)

# only the parts of 'rails/all' that metasploit-framework actually uses
begin
  require 'active_record/railtie'
rescue LoadError
  warn "activerecord not in the bundle, so database support will be disabled."
  warn "Bundle installed '--without #{Bundler.settings.without.join(' ')}'"
  warn "To clear the without option do `bundle install --without ''` " \
       "(the --without flag with an empty string) or " \
       "`rm -rf .bundle` to remove the .bundle/config manually and " \
       "then `bundle install`"
end

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