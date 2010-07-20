class Test::Unit::TestCase

	# All tests will scan for start and end lines. This ensures the task
	# actually completed and didn't hang, and that the start and end lines
	# are actually at the start and end of the task file.
	def scan_for_startend(data,thestart,theend)
		data_lines = data.split("\n")
		regex_start   = Regexp.new(thestart)
		regex_endline = Regexp.new(theend)

		assert_match regex_start, data_lines.first
		assert_match regex_endline, data_lines.last
	end

	# Tests can scan for any number of success lines. In order to pass,
	# all successes must match.
	def scan_for_successes(data,regexes)

		data_lines = data.split("\n")
		if regexes
			success = false
			target_successes = regexes.size
			count = 0
			regexes.each { |condition|
				matched = false
				re = Regexp.new(condition)
				data_lines.each {|line|
					if line =~ re
						puts re.to_s + " ... matched ... \'" + line + "\'" 
						count += 1
						matched = true
						break
					end
				}
				# A way to tell if a match was never found.
				assert matched, "Didn't see success condition '#{condition}'"
				
			}
			assert_equal target_successes, count, "Didn't get enough successes, somehow.\n"
		else
			assert true # No successes are defined, so count this as a pass.
		end
	end

	# Tests may scan for failures -- if any failure matches, the test flunks.
	def scan_for_failures(data,regexes,exceptions)

		data_lines = data.split("\n")
		if regexes
			failure = false
			regexes.each {|condition|
				re = Regexp.new(condition)
				data_lines.each {|line|
					if line =~ re
						## First check the exceptions to make sure that this wasn't among them. 
						##  The reason for exceptions is that we may want to check for generic error 
						##  messages but have specific matched strings which we know are harmless.
						
						## Guilty til proven innocent, assume it's not an exception
						not_excepted = true
						
						## But let's check anyway
						not_excepted = exceptions.map { |exception|				
							reg_exception = Regexp.new(exception)
							
							## if the exception matches here, we'll spare it
							if line =~ reg_exception 		
								return false 			
							end
						}

						## If we didn't find an exception, we have to flunk. try again, kid.
						if not_excepted
							flunk "Saw failure condition '#{condition}' in #{line}; regex matched: #{re.inspect}"
						end
					end
				}
			}
		else
			assert true # No failures, so count this as a pass.
		end
	end

end
