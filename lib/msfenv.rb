# Use bundler to load dependencies
#

# Override the normal rails default, so that msfconsole will come up in production mode instead of development mode
# unless the `--environment` flag is passed.
ENV['RAILS_ENV'] ||= 'production'

require 'pathname'
root = Pathname.new(__FILE__).expand_path.parent.parent
config = root.join('config')
require config.join('boot')

# Requiring environment will define the Metasploit::Framework::Application as the one and only Rails::Application in
# this process and cause an error if a Rails.application is already defined, such as when loading msfenv through
# msfconsole in Metasploit Pro.
unless defined?(Rails) && !Rails.application.nil?
  require config.join('environment')
end
require 'msf_autoload'
