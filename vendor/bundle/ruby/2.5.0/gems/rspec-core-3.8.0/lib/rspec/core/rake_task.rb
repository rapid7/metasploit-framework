require 'rake'
require 'rake/tasklib'
require 'rspec/support'

RSpec::Support.require_rspec_support "ruby_features"

# :nocov:
unless RSpec::Support.respond_to?(:require_rspec_core)
  RSpec::Support.define_optimized_require_for_rspec(:core) { |f| require_relative "../#{f}" }
end
# :nocov:

RSpec::Support.require_rspec_core "shell_escape"

module RSpec
  module Core
    # RSpec rake task
    #
    # @see Rakefile
    class RakeTask < ::Rake::TaskLib
      include ::Rake::DSL if defined?(::Rake::DSL)
      include RSpec::Core::ShellEscape

      # Default path to the RSpec executable.
      DEFAULT_RSPEC_PATH = File.expand_path('../../../../exe/rspec', __FILE__)

      # Default pattern for spec files.
      DEFAULT_PATTERN = 'spec/**{,/*/**}/*_spec.rb'

      # Name of task. Defaults to `:spec`.
      attr_accessor :name

      # Files matching this pattern will be loaded.
      # Defaults to `'spec/**{,/*/**}/*_spec.rb'`.
      attr_accessor :pattern

      # Files matching this pattern will be excluded.
      # Defaults to `nil`.
      attr_accessor :exclude_pattern

      # Whether or not to fail Rake when an error occurs (typically when
      # examples fail). Defaults to `true`.
      attr_accessor :fail_on_error

      # A message to print to stderr when there are failures.
      attr_accessor :failure_message

      # Use verbose output. If this is set to true, the task will print the
      # executed spec command to stdout. Defaults to `true`.
      attr_accessor :verbose

      # Command line options to pass to ruby. Defaults to `nil`.
      attr_accessor :ruby_opts

      # Path to RSpec. Defaults to the absolute path to the
      # rspec binary from the loaded rspec-core gem.
      attr_accessor :rspec_path

      # Command line options to pass to RSpec. Defaults to `nil`.
      attr_accessor :rspec_opts

      def initialize(*args, &task_block)
        @name          = args.shift || :spec
        @ruby_opts     = nil
        @rspec_opts    = nil
        @verbose       = true
        @fail_on_error = true
        @rspec_path    = DEFAULT_RSPEC_PATH
        @pattern       = DEFAULT_PATTERN

        define(args, &task_block)
      end

      # @private
      def run_task(verbose)
        command = spec_command
        puts command if verbose

        return if system(command)
        puts failure_message if failure_message

        return unless fail_on_error
        $stderr.puts "#{command} failed" if verbose
        exit $?.exitstatus || 1
      end

    private

      # @private
      def define(args, &task_block)
        desc "Run RSpec code examples" unless ::Rake.application.last_description

        task name, *args do |_, task_args|
          RakeFileUtils.__send__(:verbose, verbose) do
            task_block.call(*[self, task_args].slice(0, task_block.arity)) if task_block
            run_task verbose
          end
        end
      end

      def file_inclusion_specification
        if ENV['SPEC']
          FileList[ENV['SPEC']].sort
        elsif String === pattern && !File.exist?(pattern)
          return if rspec_opts =~ /--pattern/
          "--pattern #{escape pattern}"
        else
          # Before RSpec 3.1, we used `FileList` to get the list of matched
          # files, and then pass that along to the `rspec` command. Starting
          # with 3.1, we prefer to pass along the pattern as-is to the `rspec`
          # command, for 3 reasons:
          #
          #   * It's *much* less verbose to pass one `--pattern` option than a
          #     long list of files.
          #   * It ensures `task.pattern` and `--pattern` have the same
          #     behavior.
          #   * It fixes a bug, where
          #     `task.pattern = pattern_that_matches_no_files` would run *all*
          #     files because it would cause no pattern or file args to get
          #     passed to `rspec`, which causes all files to get run.
          #
          # However, `FileList` is *far* more flexible than the `--pattern`
          # option. Specifically, it supports individual files and directories,
          # as well as arrays of files, directories and globs, as well as other
          # `FileList` objects.
          #
          # For backwards compatibility, we have to fall back to using FileList
          # if the user has passed a `pattern` option that will not work with
          # `--pattern`.
          #
          # TODO: consider deprecating support for this and removing it in
          #   RSpec 4.
          FileList[pattern].sort.map { |file| escape file }
        end
      end

      def file_exclusion_specification
        " --exclude-pattern #{escape exclude_pattern}" if exclude_pattern
      end

      def spec_command
        cmd_parts = []
        cmd_parts << RUBY
        cmd_parts << ruby_opts
        cmd_parts << rspec_load_path
        cmd_parts << escape(rspec_path)
        cmd_parts << file_inclusion_specification
        cmd_parts << file_exclusion_specification
        cmd_parts << rspec_opts
        cmd_parts.flatten.reject(&blank).join(" ")
      end

      def blank
        lambda { |s| s.nil? || s == "" }
      end

      def rspec_load_path
        @rspec_load_path ||= begin
          core_and_support = $LOAD_PATH.grep(
            /#{File::SEPARATOR}rspec-(core|support)[^#{File::SEPARATOR}]*#{File::SEPARATOR}lib/
          ).uniq

          "-I#{core_and_support.map { |file| escape file }.join(File::PATH_SEPARATOR)}"
        end
      end
    end
  end
end
