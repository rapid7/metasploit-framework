require 'rubygems'
require 'bundler'
Bundler.setup(:default, :test)

# add project lib directory to load path
spec_pathname = Pathname.new(__FILE__).dirname
root_pathname = spec_pathname.join('..').expand_path
lib_pathname = root_pathname.join('lib')
$LOAD_PATH.unshift(lib_pathname.to_s)

require 'rspec/core'

# Requires supporting ruby files with custom matchers and macros, etc,
# in spec/support/ and its subdirectories.
support_glob = root_pathname.join('spec', 'support', '**', '*.rb')

Dir.glob(support_glob) do |path|
  require path
end

RSpec.configure do |config|
  config.mock_with :rspec
end

