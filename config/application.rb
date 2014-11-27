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
require 'metasploit/framework/database'

module Metasploit
  module Framework
    class Application < Rails::Application
      include Metasploit::Framework::CommonEngine

      config.paths['config/database'] = [Metasploit::Framework::Database.configurations_pathname.try(:to_path)]
    end
  end
end

# Silence warnings about this defaulting to true
I18n.enforce_available_locales = true
