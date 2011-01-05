##
## $Id$
##

$:.unshift(File.expand_path(File.dirname(__FILE__)))
require 'regexr'

module MsfTest

class MsfTestCaseHelper

	## This module consists of assert helper methods for regexing logs
	##  Use it in conjunction with test/unit
	
	def initialize
		@debug = false
		@regexr = Regexr.new(@debug)
	end
	
	def complete?(data,first,last)
		@regexr.verify_start_and_end(data,first,last)
	end

	def all_successes_exist?(data, regex_strings)
		if regex_strings
			regex_strings.each { |regex_string|
				return false unless @regexr.ensure_exists_in_data(data,regex_string) 
			}
		end
	end
	
	def no_failures_exist?(data, regex_strings, exception_strings)
		if regex_strings
			regex_strings.each { |regex_string|
				return false unless @regexr.ensure_doesnt_exist_in_data_unless(data,regex_string,exception_strings)
			}
		end
	end

end

end
