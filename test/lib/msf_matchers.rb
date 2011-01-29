$:.unshift(File.join((File.dirname(__FILE__))))
require 'regexr'

module MsfMatchers

	class ContainAllSuccesses

		def initialize(successes)
			@successes = successes
			@r = Regexr.new(true)
		end

		def matches?(data)
			@data = data
			@actual = @r.find_strings_that_dont_exist_in_data(@data,@successes)
			return true if !@actual
		end

		def failure_message
			"expected all successes, but didn't find '#{@actual}'"
		end

		def negative_failure_message
			"expected to miss successes but found'm all :("
		end

		#alias :have_all_successes :contain_all_successes
	end
	
	def contain_all_successes(successes)
		ContainAllSuccesses.new(successes)
	end
	
	class ContainNoFailuresExcept

		def initialize(failures,exceptions)
			@failures = failures
			@exceptions = exceptions
			@r = Regexr.new(true)
		end

		def matches?(data)
			@data = data
			@actual = @r.find_strings_that_exist_in_data_except(@data,@failures,@exceptions)
			return false if @actual
		end

		def failure_message
			"expected no failure to be found, but found this: '#{@actual}'"
		end

		def negative_falure_message
			"expected to find failures, but didn't find any :("
		end

		#alias :have_no_failures :contain_no_failures
	end

	def contain_no_failures_except(failures,exceptions)
		ContainNoFailuresExcept.new(failures,exceptions)
	end

	
end
