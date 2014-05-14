#
# Use bundler to load dependencies
#

# Override the normal rails default, so that msfconsole will come up in production mode instead of development mode
# unless the `--environment` flag is passed.
ENV['RAILS_ENV'] ||= 'production'

require 'pathname'
root = Pathname.new(__FILE__).expand_path.parent.parent
config = root.join('config')
require config.join('boot')
require config.join('environment')
