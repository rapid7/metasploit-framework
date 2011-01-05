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

	# Scan for a success line. In order to pass, the string must exist in the data
	def ensure_exists_in_data(data,regex_string)
			data_lines = data.split("\n")
			re = Regexp.new(regex_string, @case_insensitive)
	
			data_lines.each {|line|
				if line =~ re
					return true
				end
			}

		return false
	end

	# Scan for a fail line. In order to pass, the string must not exist in the data
	def ensure_doesnt_exist_in_data(data,regex_string)
			data_lines = data.split("\n")
			re = Regexp.new(regex_string, @case_insensitive)
	
			data_lines.each {|line|
				if line =~ re
					return false
				end
			}

		return true
	end

	# Scan for a fail line. In order to pass, the string must not exist in the data
	def ensure_doesnt_exist_in_data_unless(data, regex_string, exceptions)
			data_lines = data.split("\n")
			data_lines.each {|line|
				if line =~ Regexp.new(regex_string, @case_insensitive)
					exceptions.each { |exception|
						if line =~ Regexp.new(exception, @case_insensitive)
							return true
						end
					}
					return false
				end
			}
		return true
	end

	# Scan for any number of success lines. In order to pass, all successes must match.
	def ensure_all_exist_in_data(data,regexes=[])
		data_lines = data.split("\n")
		if regexes
			target_successes = regexes.size
			success_count = 0
			regexes.each { |condition|
				matched = false
				re = Regexp.new(condition, @case_insensitive)
				data_lines.each {|line|
					if line =~ re
						if @verbose
							puts "DEBUG: matched success: " + line
						end
						success_count += 1
						matched = true
						break
					end
				}
				
				# A way to tell if a match was never found.
				if !matched
					if @verbose 
						puts "DEBUG: Didn't see success condition '#{condition}'"
					end
					return false
				end
			}
			
			if target_successes == success_count
				if @verbose 	
					puts "DEBUG: Woot, got all successes"
				end
				return true
			else 
				if @verbose
					 puts "DEBUG: Didn't get enough successes, failing. (" + count + "/" + target_successes + ")"
				end
				return false
			end
		else
			return true # No successes are defined, so count this as a pass (true).
		end
	end

	# Scan for failures -- if any single failure matches, the test returns true.
	def ensure_none_exist_in_data(data,regexes=[],exceptions=[])
		data_lines = data.split("\n")
		if regexes
			regexes.each { |condition|
				## for each failure condition that we've been passed 
				re = Regexp.new(condition, @case_insensitive)

				## assume we're okay
				okay = true				

				data_lines.each { |line|

					if re =~ line
						okay = false # oh, we found a match

						if @verbose
							puts "DEBUG: Matched failure: " + line
						end									


						# but let's check the exceptions
						exceptions.map { |exception|
							reg_exception = Regexp.new(exception, @case_insensitive)

							# If the exception matches here, we'll spare it
							if reg_exception =~ line 
								if @verbose
									puts "DEBUG: but \'" + line + "\' is an exception, we can ignore it."
								end									
								okay = true
								break
							end
						}

						# If we didn't find an exception, we have to fail it. do not pass go. 
						if !okay
							if @verbose
								puts "DEBUG: Saw failure condition '#{condition}' in #{line}; regex matched: #{re.inspect}"
							end
							return false 
						end
					end
				}
			}
		else
			return false # we gots no failures, so count this as a pass.
		end
	end
end
