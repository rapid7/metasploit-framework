require 'simplecov'
require 'pathname'

SimpleCov.start do
  add_filter '/spec/'
  add_filter '/config/'
  add_filter '/vendor/'
end if ENV["COVERAGE"]

require 'rspec'
require 'net/ntlm'

# add project lib directory to load path
spec_pathname = Pathname.new(__FILE__).dirname
root_pathname = spec_pathname.join('..').expand_path
# Requires supporting ruby files with custom matchers and macros, etc,
# in spec/support/ and its subdirectories.
support_glob = root_pathname.join('spec', 'support', '**', '*.rb')

Dir.glob(support_glob) do |path|
  require path
end
