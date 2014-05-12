#
# Use bundler to load dependencies
#

require 'pathname'
root = Pathname.new(__FILE__).expand_path.parent.parent
config = root.join('config')
require config.join('boot')
require config.join('environment')
