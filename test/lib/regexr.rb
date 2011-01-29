## This class consists of helper methods for regexing logs
##
## TODO - clean up the style. looks like it was written in the early 90s
##
## $Id$

class Regexr

	def initialize(verbose=false, case_insensitive=true)
		@verbose = verbose
		@case_insensitive = case_insensitive
	end

	# Check for the beginning line. Handy when you need to ensure a log has started
	def verify_start(data,the_start)
		data_lines = data.split("\n")
		regex_start = Regexp.new(the_start, @case_insensitive)
		if @verbose
			puts "Testing: " + the_start + " =~ " + data_lines.first
		end
		
		return regex_start =~ data_lines.first
	end

	# Check for end line. Handy when you need to ensure a log has completed.
	def verify_end(data,the_end)
		data_lines = data.split("\n")
		regex_end = Regexp.new(the_end, @case_insensitive)
		if @verbose
			puts "Testing: " + the_end + " =~ " + data_lines.last
		end
		return regex_end =~ data_lines.last
	end

	# Check for the beginning and end lines. Handy when you need to ensure a log has started & completed
	def verify_start_and_end(data,the_start,the_end)
		data_lines = data.split("\n")
		regex_start   = Regexp.new(the_start, @case_insensitive)
		regex_end = Regexp.new(the_end, @case_insensitive)

		if @verbose
			puts "Testing: " + the_start + " =~ " + data_lines.first
			puts "Testing: " + the_end + " =~ " + data_lines.last
		end

		if regex_start =~ data_lines.first
			return regex_end =~ data_lines.last
		end
		
		return false
	end

	# Scan for any number of success lines. In order to pass, all successes must match.
	def find_strings_that_dont_exist_in_data(data,regexes=[])
		data_lines = data.split("\n")
		if regexes
			target_successes = regexes.size
			success_count = 0
			regexes.each { |condition|
				if @verbose
					puts "DEBUG: testing regex for existence: #{condition}"
				end

				## assume we haven't got it
				matched = false
				 
				re = Regexp.new(condition, @case_insensitive)
				
				## for each of our data lines
				data_lines.each {|line|
				
					## if it's a match
					if line =~ re
					
						if @verbose
							puts "DEBUG: matched regex #{re.to_s}: with #{line}"
						end

						## and set matched properly
						matched = true
						
						break ## greedy success!
					end
				}
				
				if !matched
					return condition ## return this string, it wasn't found.
				end
				
				
			}
		else
			nil # No successes are defined, so count this as a pass (nil).
		end
		
		nil ## got all successes, woot!
	end

	# Scan for failures -- if any single failure matches, the test returns true.
	def find_strings_that_exist_in_data_except(data,regexes=[],exceptions=[])
		data_lines = data.split("\n")
		if regexes
			regexes.each { |condition|
				if @verbose
					puts "DEBUG: testing regex for existence: #{condition}"
				end

				## for each failure condition that we've been passed 
				re = Regexp.new(condition, @case_insensitive)

				## assume we're okay
				match = false				

				data_lines.each { |line|

					if re =~ line
					
						if @verbose
							puts "DEBUG: matched #{re.to_s} in #{line}"
						end	
	
						match = true # oh, we found a match
						
						# but let's check the exceptions
						exceptions.map { |exception|
							reg_exception = Regexp.new(exception, @case_insensitive)

							# If the exception matches here, we'll spare it
							if reg_exception =~ line
								if @verbose
									puts "DEBUG: but #{line} is an exception, we can ignore it."
								end									
								match = false
								break
							end
						}

						# If we didn't find an exception, we have to fail it. do not pass go. 
						if match
							if @verbose
								puts "DEBUG: Saw failure condition '#{condition}' in #{line}; regex matched: #{re.inspect}. no exceptions found."
							end
							
							return condition ## fail early
						end
					end
				}
			}
		else
			nil # we gots no failures, so count this as a pass.
		end
		
		nil ## no failures found!
	end
end
