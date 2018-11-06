# encoding: UTF-8

$:.push(File.dirname(__FILE__))

require 'rspec'
require 'arel-helpers'
require 'fileutils'
require 'pry-byebug'

require 'env'

def silence(&block)
  original_stdout = $stdout
  $stdout = StringIO.new
  begin
    yield
  ensure
    $stdout = original_stdout
  end
end

RSpec.configure do |config|
  config.mock_with :rr

  config.before(:each) do
    ArelHelpers::Env.establish_connection
    ArelHelpers::Env.reset
    silence { ArelHelpers::Env.migrate }
  end
end
