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

  # Check for the beginning and end lines. Handy when you need to ensure a log has started & completed
  def verify_start_and_end(data,the_start,the_end)
    return false unless data
    
    data_lines = data.split("\n")
    regex_start   = Regexp.new(the_start, @case_insensitive)
    regex_end = Regexp.new(the_end, @case_insensitive)

    if regex_start =~ data_lines.first
      return regex_end =~ data_lines.last
    end
    
    return false
  end

  # Scan for any number of success lines. In order to pass, all successes must match.
  def find_strings_that_dont_exist_in_data(data,regexes=[])
    return false unless data

    data_lines = data.split("\n")
    
    return nil unless regexes ## count as a pass
    
    if regexes
      target_successes = regexes.size
      success_count = 0
      regexes.each { |condition|

        ## assume we haven't got it
        found = false
         
        re = Regexp.new(condition, @case_insensitive)
        
        ## for each of our data lines
        data_lines.each {|line|
        
          ## if it's a match
          if line =~ re
            found = true
            break ## success!
          end
        }
        
        if !found
          return condition ## return this string, it wasn't found.
        end
      }
    end
    
    nil ## got all successes, woot!
  end

  # Scan for failures -- if any single failure matches, the test returns true.
  def find_strings_that_exist_in_data_except(data,regexes=[],exceptions=[])

    return false unless data

    data_lines = data.split("\n")
    
    return nil unless regexes ## count as a pass

    regexes.each { |condition|

      ## for each failure condition that we've been passed 
      re = Regexp.new(condition, @case_insensitive)

      ## assume we're okay
      found = false				

      data_lines.each { |line|
        if re =~ line
          found = true # oh, we found a match
          
          # but let's check the exceptions
          exceptions.map { |exception|
            reg_exception = Regexp.new(exception, @case_insensitive)

            # If the exception matches here, we'll spare it
            if reg_exception =~ line
              found = false
              break
            end
          }

          # If we didn't find an exception, we have to fail it. do not pass go. 
          return condition if found
        end
      }
    }
    
    nil ## no failures found!
  end
end
