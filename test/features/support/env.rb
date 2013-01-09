#Cucumber automation environment setup class for MSF Testing

require 'cucumber'
require 'aruba/cucumber'
require_relative 'test_config'

Before do
#before automation execution methods go here

	@dirs = ["/Users/gary/rapid7/framework"]
	@aruba_timeout_seconds = 150
end

Before('@slow_process') do 
	@aruba_io_wait_seconds = 150
end

@After
#after automation execution methods go here


