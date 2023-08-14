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

      register_options(
        [
          OptString.new("TestName", [false, "Run a specified test method name.", nil]),
        ], self.class
      )
    end

    def run_all_tests
      tests = datastore['TestName'].present? ? [datastore['TestName'].to_sym] : self.methods.select { |m| m.to_s =~ /^test_/ }
      tests.each { |test_method|
        begin
          unless respond_to?(test_method)
            print_error("test method #{test_method} not found")
            next
          end
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
      @current_it_msg = msg
      @tests += 1
      begin
        result = block.call
        unless result
          @failures += 1
          print_error("FAILED: #{error}") if error
          @current_it_msg = nil
          print_error("FAILED: #{msg}")
          return
        end
      rescue SkipTestError => e
        @skipped += 1
        @current_it_msg = nil
        print_status("SKIPPED: #{msg} (#{e.message})")
        return
      rescue ::Exception => e
        @failures += 1
        print_error("FAILED: #{msg}")
        print_error("Exception: #{e.class}: #{e}")
        dlog("Exception in testing - #{msg}")
        dlog("Call stack: #{e.backtrace.join("\n")}")
        return
      ensure
        @current_it_msg = nil
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

    # When printing to console, additionally prepend the current test name
    [
      :print,
      :print_line,
      :print_status,
      :print_good,

      :print_warning,
      :print_error,
      :print_bad,
    ].each do |method|
      define_method(method) do |msg|
        super(@current_it_msg ? "[#{@current_it_msg}] #{msg}" : msg)
      end
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

  module ModuleTest::PostTestFileSystem
    def initialize(info = {})
      super

      register_options(
        [
          OptBool.new("AddEntropy", [false, "Add entropy token to file and directory names.", true]),
          OptString.new('BaseDirectoryName', [true, 'Directory name to create', 'meterpreter-test-dir']),
          OptString.new("BaseFileName", [true, "File/dir base name", "meterpreter-test"]),
        ], self.class
      )

      @directory_stack = []
    end

    def push_test_directory
      @directory_stack.push(_file_system.pwd)

      # Find the temp directory
      tmp = _file_system.get_env("TMP") || _file_system.get_env("TMPDIR")
      # mettle fallback
      tmp = '/tmp' if tmp.nil? && _file_system.directory?('/tmp')
      raise "Could not find tmp directory" if tmp == nil || !_file_system.directory?(tmp)

      vprint_status("Setup: changing working directory to tmp: #{tmp}")
      _file_system.cd(tmp)

      vprint_status("Setup: Creating clean directory")

      if datastore["AddEntropy"]
        entropy_value = '-' + ('a'..'z').to_a.shuffle[0, 8].join
      else
        entropy_value = ""
      end
      clean_test_directory = datastore['BaseDirectoryName'] + entropy_value
      _file_system.mkdir(clean_test_directory)
      _file_system.cd(clean_test_directory)

      vprint_status("Setup: Now in #{_file_system.pwd}")
    end

    def pop_test_directory
      previous_directory = @directory_stack.pop
      unless previous_directory.nil?
        vprint_status("Cleanup: changing working directory back to #{previous_directory}")
        _file_system.cd(previous_directory)
      end
    end

    # Private PostFile wrapper to ensure we don't clobber the test module's namespace with the Msf::Post::File mixin methods
    class FileSystem
      include Msf::Post::File

      def initialize(mod)
        @mod = mod
        @session = mod.session
      end

      private

      def vprint_status(s)
        @mod.vprint_status(s)
      end

      def register_dir_for_cleanup(path)
      end

      attr_reader :session
    end

    def _file_system
      FileSystem.new(self)
    end
  end
end
