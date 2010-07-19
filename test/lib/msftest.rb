
class Test::Unit::TestCase

	# All tests will scan for start and end lines. This ensures the task
	# actually completed and didn't hang, and that the start and end lines
	# are actually at the start and end of the task file.
	def scan_for_startend(data,regexes,component)
		data_lines = data.split("\n")
		regex_start   = Regexp.new(regexes[component.to_s + "_startline"])
		regex_endline = Regexp.new(regexes[component.to_s + "_endline"])
		assert_match regex_start, data_lines.first
		assert_match regex_endline, data_lines.last
	end

	# Tests can scan for any number of success lines. In order to pass,
	# all successes must match.
	def scan_for_successes(data,regexes,component)
		data_lines = data.split("\n")
		if regexes[component.to_s + "_successes"]
			success = false
			target_successes = regexes[component.to_s + "_successes"].size
			count = 0
			regexes[component.to_s + "_successes"].each { |condition|
				matched = false
				re = Regexp.new(condition[1])
				data_lines.each {|line|
					if line =~ re
						puts " ... found."
						count += 1
						matched = condition[0]
						break
					end
				}
				# A way to tell if a match was never found.
				assert_equal condition[0], matched, "Didn't see success condition '#{condition[0]}'; regex failed: #{re.inspect}\n"
			}
			assert_equal target_successes, count, "Didn't get enough successes, somehow.\n"
		else
			assert true # No successes are defined, so count this as a pass.
		end
	end

	# Tests may scan for failures -- if any failure matches, the test flunks.
	def scan_for_failures(data,regexes,component,exceptions)
		data_lines = data.split("\n")
		if regexes[component.to_s + "_failures"]
			failure = false
			regexes[component.to_s + "_failures"].each {|condition|
				re = Regexp.new(condition[1])
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
							flunk "Saw failure condition '#{condition[0]}'; regex matched: #{re.inspect}"
						end
					end
				}
			}
		else
			assert true # No failures looked for, so count this as a pass.
		end
	end

end
