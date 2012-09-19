$LOAD_PATH.unshift(File.dirname(__FILE__))
$LOAD_PATH.unshift(File.expand_path('../lib', File.dirname(__FILE__)))

require 'rubygems'
require 'bundler/setup'
require 'fssm'

require 'rspec'

RSpec.configure do |config|
  config.before :all do
    @watch_root = FSSM::Pathname.new(__FILE__).dirname.join('root').expand_path
  end
end
