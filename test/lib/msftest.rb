## This class consists of assert helper methods for regexing logs
##
## $id$
$:.unshift(File.expand_path(File.dirname(__FILE__)) 

require 'regexr'
require 'test/unit'

class MSFTest < Test::Unit::TestCase

	def initialize 
		@case_insensitive = true
		@regexr = Regexr.new
	end

	def assert_complete(data,thestart,theend)
		assert_true @regexr.verify_start_and_end(data,thestart,theend), "The start or end did not match the expected string"
	end

	def assert_all_successes(data, regexes)
		assert_true @regexr.scan_for_successes(data,regexes), "All strings were found in the data"
	end

	def assert_no_failures(data, regexes, exceptions)
		assert_true @regexr.scan_for_failures(data,regexes,exceptions), "A non-exccepted failure was found in the data"
	end
end
