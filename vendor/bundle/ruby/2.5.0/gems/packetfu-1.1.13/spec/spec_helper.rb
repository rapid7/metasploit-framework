require 'coveralls'
Coveralls.wear!

puts "rspec #{RSpec::Core::Version::STRING}"
if RSpec::Core::Version::STRING[0] == '3'
  require 'rspec/its'
  RSpec.configure do |config|
    #config.raise_errors_for_deprecations!
    config.expect_with :rspec do |c|
      c.syntax = [:expect, :should]
    end
  end
end

require 'packetfu/common'

