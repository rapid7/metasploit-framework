## This class consists of assert helper methods for regexing logs
##
## $id$
$:.unshift(File.expand_path(File.dirname(__FILE__)))

require 'regexr'
require 'test/unit'

class MsfTest < Test::Unit::TestCase

	def setup 
		super		
		@case_insensitive = true
		@regexr = Regexr.new
	end

	def assert_complete(data,first,last)
		assert_not_nil @regexr.verify_start(data,first), "The start string " + data.split("\n").first + " did not match the expected string: " + first
		assert_not_nil @regexr.verify_end(data,last), "The end string " + data.split("\n").last + " did not match the expected string: " + last
	end

	def assert_all_successes(data, regex_strings)
		regex_strings.each { |regex_string|
			assert_true @regexr.ensure_exists_in_data(data,regex_string), "The string " + regex_string + " was not found in the data."
		}
	end

	def assert_no_failures(data, regex_strings, exception_strings)
		regex_strings.each { |regex_string|
			assert_true @regexr.ensure_doesnt_exist_in_data_unless(data,regex_string,exception_strings), "The string " + regex_string + " was found in the the data, and no exception was found."
		}
	end
end
