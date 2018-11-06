# frozen_string_literal: true

require "English"

#
# Code coverage for ruby 1.9. Please check out README for a full introduction.
#
# Coverage may be inaccurate under JRUBY.
if defined?(JRUBY_VERSION) && defined?(JRuby)

  # @see https://github.com/jruby/jruby/issues/1196
  # @see https://github.com/metricfu/metric_fu/pull/226
  # @see https://github.com/colszowka/simplecov/issues/420
  # @see https://github.com/colszowka/simplecov/issues/86
  # @see https://jira.codehaus.org/browse/JRUBY-6106

  unless org.jruby.RubyInstanceConfig.FULL_TRACE_ENABLED
    warn 'Coverage may be inaccurate; set the "--debug" command line option,' \
      ' or do JRUBY_OPTS="--debug"' \
      ' or set the "debug.fullTrace=true" option in your .jrubyrc'
  end
end
module SimpleCov
  class << self
    attr_accessor :running
    attr_accessor :pid
    attr_reader :exit_exception

    #
    # Sets up SimpleCov to run against your project.
    # You can optionally specify a profile to use as well as configuration with a block:
    #   SimpleCov.start
    #    OR
    #   SimpleCov.start 'rails' # using rails profile
    #    OR
    #   SimpleCov.start do
    #     add_filter 'test'
    #   end
    #     OR
    #   SimpleCov.start 'rails' do
    #     add_filter 'test'
    #   end
    #
    # Please check out the RDoc for SimpleCov::Configuration to find about available config options
    #
    def start(profile = nil, &block)
      if SimpleCov.usable?
        load_profile(profile) if profile
        configure(&block) if block_given?
        @result = nil
        self.running = true
        self.pid = Process.pid
        Coverage.start
      else
        warn "WARNING: SimpleCov is activated, but you're not running Ruby 1.9+ - no coverage analysis will happen"
        warn "Starting with SimpleCov 1.0.0, even no-op compatibility with Ruby <= 1.8 will be entirely dropped."
        false
      end
    end

    #
    # Finds files that were to be tracked but were not loaded and initializes
    # the line-by-line coverage to zero (if relevant) or nil (comments / whitespace etc).
    #
    def add_not_loaded_files(result)
      if tracked_files
        result = result.dup
        Dir[tracked_files].each do |file|
          absolute = File.expand_path(file)

          result[absolute] ||= LinesClassifier.new.classify(File.foreach(absolute))
        end
      end

      result
    end

    #
    # Returns the result for the current coverage run, merging it across test suites
    # from cache using SimpleCov::ResultMerger if use_merging is activated (default)
    #
    def result
      return @result if result?

      # Collect our coverage result
      if running
        @result = SimpleCov::Result.new add_not_loaded_files(Coverage.result)
      end

      # If we're using merging of results, store the current result
      # first (if there is one), then merge the results and return those
      if use_merging
        SimpleCov::ResultMerger.store_result(@result) if result?
        @result = SimpleCov::ResultMerger.merged_result
      end

      @result
    ensure
      self.running = false
    end

    #
    # Returns nil if the result has not been computed
    # Otherwise, returns the result
    #
    def result?
      defined?(@result) && @result
    end

    #
    # Applies the configured filters to the given array of SimpleCov::SourceFile items
    #
    def filtered(files)
      result = files.clone
      filters.each do |filter|
        result = result.reject { |source_file| filter.matches?(source_file) }
      end
      SimpleCov::FileList.new result
    end

    #
    # Applies the configured groups to the given array of SimpleCov::SourceFile items
    #
    def grouped(files)
      grouped = {}
      grouped_files = []
      groups.each do |name, filter|
        grouped[name] = SimpleCov::FileList.new(files.select { |source_file| filter.matches?(source_file) })
        grouped_files += grouped[name]
      end
      if !groups.empty? && !(other_files = files.reject { |source_file| grouped_files.include?(source_file) }).empty?
        grouped["Ungrouped"] = SimpleCov::FileList.new(other_files)
      end
      grouped
    end

    #
    # Applies the profile of given name on SimpleCov configuration
    #
    def load_profile(name)
      profiles.load(name)
    end

    def load_adapter(name)
      warn "#{Kernel.caller.first}: [DEPRECATION] #load_adapter is deprecated. Use #load_profile instead."
      load_profile(name)
    end

    #
    # Checks whether we're on a proper version of Ruby (likely 1.9+) which
    # provides coverage support
    #
    def usable?
      return @usable if defined?(@usable) && !@usable.nil?

      @usable = begin
        require "coverage"
        require "simplecov/jruby_fix"
        true
      rescue LoadError
        false
      end
    end

    #
    # Clear out the previously cached .result. Primarily useful in testing
    #
    def clear_result
      @result = nil
    end

    #
    # Capture the current exception if it exists
    # This will get called inside the at_exit block
    #
    def set_exit_exception
      @exit_exception = $ERROR_INFO
    end

    #
    # Returns the exit status from the exit exception
    #
    def exit_status_from_exception
      return SimpleCov::ExitCodes::SUCCESS unless exit_exception

      if exit_exception.is_a?(SystemExit)
        exit_exception.status
      else
        SimpleCov::ExitCodes::EXCEPTION
      end
    end

    # @api private
    #
    # Called from at_exit block
    #
    def run_exit_tasks!
      exit_status = SimpleCov.exit_status_from_exception

      SimpleCov.at_exit.call

      exit_status = SimpleCov.process_result(SimpleCov.result, exit_status)

      # Force exit with stored status (see github issue #5)
      # unless it's nil or 0 (see github issue #281)
      Kernel.exit exit_status if exit_status && exit_status > 0
    end

    # @api private
    #
    # Usage:
    #   exit_status = SimpleCov.process_result(SimpleCov.result, exit_status)
    #
    def process_result(result, exit_status)
      return exit_status unless SimpleCov.result? # Result has been computed
      return exit_status if exit_status != SimpleCov::ExitCodes::SUCCESS # Existing errors

      covered_percent = result.covered_percent.round(2)
      result_exit_status = result_exit_status(result, covered_percent)
      if result_exit_status == SimpleCov::ExitCodes::SUCCESS # No result errors
        write_last_run(covered_percent)
      end
      result_exit_status
    end

    # @api private
    #
    # rubocop:disable Metrics/MethodLength
    def result_exit_status(result, covered_percent)
      covered_percentages = result.covered_percentages.map { |percentage| percentage.round(2) }
      if covered_percent < SimpleCov.minimum_coverage
        $stderr.printf("Coverage (%.2f%%) is below the expected minimum coverage (%.2f%%).\n", covered_percent, SimpleCov.minimum_coverage)
        SimpleCov::ExitCodes::MINIMUM_COVERAGE
      elsif covered_percentages.any? { |p| p < SimpleCov.minimum_coverage_by_file }
        $stderr.printf("File (%s) is only (%.2f%%) covered. This is below the expected minimum coverage per file of (%.2f%%).\n", result.least_covered_file, covered_percentages.min, SimpleCov.minimum_coverage_by_file)
        SimpleCov::ExitCodes::MINIMUM_COVERAGE
      elsif (last_run = SimpleCov::LastRun.read)
        coverage_diff = last_run["result"]["covered_percent"] - covered_percent
        if coverage_diff > SimpleCov.maximum_coverage_drop
          $stderr.printf("Coverage has dropped by %.2f%% since the last time (maximum allowed: %.2f%%).\n", coverage_diff, SimpleCov.maximum_coverage_drop)
          SimpleCov::ExitCodes::MAXIMUM_COVERAGE_DROP
        else
          SimpleCov::ExitCodes::SUCCESS
        end
      else
        SimpleCov::ExitCodes::SUCCESS
      end
    end
    # rubocop:enable Metrics/MethodLength

    #
    # @api private
    #
    def write_last_run(covered_percent)
      SimpleCov::LastRun.write(:result => {:covered_percent => covered_percent})
    end
  end
end

$LOAD_PATH.unshift(File.join(File.dirname(__FILE__)))
require "simplecov/configuration"
SimpleCov.send :extend, SimpleCov::Configuration
require "simplecov/exit_codes"
require "simplecov/profiles"
require "simplecov/source_file"
require "simplecov/file_list"
require "simplecov/result"
require "simplecov/filter"
require "simplecov/formatter"
require "simplecov/last_run"
require "simplecov/lines_classifier"
require "simplecov/raw_coverage"
require "simplecov/result_merger"
require "simplecov/command_guesser"
require "simplecov/version"

# Load default config
require "simplecov/defaults" unless ENV["SIMPLECOV_NO_DEFAULTS"]

# Load Rails integration (only for Rails 3, see #113)
require "simplecov/railtie" if defined? Rails::Railtie
