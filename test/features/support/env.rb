#Cucumber automation environment setup class for MSF Testing

require 'cucumber'
require 'aruba/cucumber'
require_relative 'test_config'

Before do
	# Automatically find the framework path
	default_path = File.join(File.expand_path(File.dirname(__FILE__)), '../../../')

	# Add more paths manually if needed. For example:
	# "/Users/gary/rapid7/framework"
	@dirs = [default_path]

	@aruba_timeout_seconds = 150
end

Before('@slow_process') do 
	@aruba_io_wait_seconds = 150
end

@After
#after automation execution methods go here


