require 'bundler/setup'
Bundler.setup
require 'simplecov'
SimpleCov.start

require 'pry'
require 'xdr'

__dir__ = File.dirname(__FILE__)

Dir["#{__dir__}/support/**/*.rb"].each { |f| require f }

RSpec.configure do |config|
  
end
