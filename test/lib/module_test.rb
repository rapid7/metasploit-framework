require 'rex/stopwatch'

module Msf
  module ModuleTest
    attr_accessor :tests
    attr_accessor :failures
    attr_accessor :skipped

    class SkipTestError < ::Exception
    end

    def initialize(info = {})
      @tests = 0
      @failures = 0
      @skipped = 0
      super
    end

    def run_all_tests
      tests = self.methods.select { |m| m.to_s =~ /^test_/ }
      tests.each { |test_method|
        begin
          self.send(test_method)
        rescue SkipTestError => e
          # If the entire def is skipped, increment tests and skip count
          @tests += 1
          @skipped += 1
          print_status("SKIPPED: def #{test_method} (#{e.message})")
        end
      }
    end

    def skip(msg = "No reason given")
      raise SkipTestError, msg
    end

    def it(msg = "", &block)
      @tests += 1
      begin
        result = block.call
        unless result
          print_error("FAILED: #{msg}")
          print_error("FAILED: #{error}") if error
          @failures += 1
          return
        end
      rescue SkipTestError => e
        @skipped += 1
        print_status("SKIPPED: #{msg} (#{e.message})")
      rescue ::Exception => e
        @failures += 1
        print_error("FAILED: #{msg}")
        print_error("Exception: #{e.class}: #{e}")
        dlog("Exception in testing - #{msg}")
        dlog("Call stack: #{e.backtrace.join("\n")}")
        return
      end

      print_good("#{msg}")
    end

    def pending(msg = "", &block)
      print_status("PENDING: #{msg}")
    end

    # @return [Integer] The number of tests that have passed
    def passed
      @tests - @failures
    end
  end

  module ModuleTest::PostTest
    include ModuleTest
    def run
      print_status("Running against session #{datastore["SESSION"]}")
      print_status("Session type is #{session.type} and platform is #{session.platform}")

      @tests = 0
      @failures = 0
      @skipped = 0

      _res, elapsed_time = Rex::Stopwatch.elapsed_time do
        run_all_tests
      end

      vprint_status("Testing complete in #{elapsed_time.round(2)} seconds")
      status = "Passed: #{passed}; Failed: #{@failures}; Skipped: #{@skipped}"
      if @failures > 0
        print_error(status)
      else
        print_status(status)
      end
    end
  end
end
