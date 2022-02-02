$:.unshift(File.join((File.dirname(__FILE__))))
require 'regexr'

module MsfTest

module MsfMatchers

  class ContainACompleteTest

    def initialize()
      @r = Regexr.new(true)
    end

    def matches?(data)
      @data = data
      return @r.verify_start_and_end(@data,"meterpreter_functional_test_start", "meterpreter_functional_test_end")
    end

    def failure_message
      "Beginning or end was incorrect."
    end

    def negative_failure_message
      "Expected to find a no beginning or end, but it matched."
    end

  end
  
  def contain_a_complete_test
    ContainACompleteTest.new
  end

  class ContainAllSuccesses

    def initialize(successes=[])
      @successes = successes
      @r = Regexr.new(true)
    end

    def matches?(data)
      @data = data
      @string = @r.find_strings_that_dont_exist_in_data(@data,@successes)
      return true if !@string
      nil
    end

    def failure_message
      "expected all successes, but didn't find '#{@string}'"
    end

    def negative_failure_message
      "expected to miss successes but found'm all :("
    end

    #alias :have_all_successes :contain_all_successes
  end
  
  def contain_all_successes(successes=[])
    ContainAllSuccesses.new(successes)
  end
  
  class ContainNoFailuresExcept

    def initialize(failures=[],exceptions=[])
      @failures = failures
      @exceptions = exceptions
      @r = Regexr.new(true)
    end

    def matches?(data)
      @data = data
      @string = @r.find_strings_that_exist_in_data_except(@data,@failures,@exceptions)
      return true if !@string
      nil
    end

    def failure_message
      "expected no failure to be found, but found this: '#{@string}'"
    end

    def negative_falure_message
      "expected to find failures, but didn't find any :("
    end

    #alias :have_no_failures :contain_no_failures
  end

  def contain_no_failures_except(failures=[],exceptions=[])
    ContainNoFailuresExcept.new(failures,exceptions)
  end

  
end
end
