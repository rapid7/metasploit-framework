require 'rspec/support'
require 'rspec/support/spec/in_sub_process'

RSpec::Support.require_rspec_support "spec/deprecation_helpers"
RSpec::Support.require_rspec_support "spec/with_isolated_stderr"
RSpec::Support.require_rspec_support "spec/stderr_splitter"
RSpec::Support.require_rspec_support "spec/formatting_support"
RSpec::Support.require_rspec_support "spec/with_isolated_directory"
RSpec::Support.require_rspec_support "ruby_features"

warning_preventer = $stderr = RSpec::Support::StdErrSplitter.new($stderr)

RSpec.configure do |c|
  c.include RSpecHelpers
  c.include RSpec::Support::WithIsolatedStdErr
  c.include RSpec::Support::FormattingSupport
  c.include RSpec::Support::InSubProcess

  unless defined?(Debugger) # debugger causes warnings when used
    c.before do
      warning_preventer.reset!
    end

    c.after do
      warning_preventer.verify_no_warnings!
    end
  end

  if c.files_to_run.one?
    c.full_backtrace = true
    c.default_formatter = 'doc'
  end

  c.filter_run_when_matching :focus

  c.example_status_persistence_file_path = "./spec/examples.txt"

  c.define_derived_metadata :failing_on_appveyor do |meta|
    meta[:pending] ||= "This spec fails on AppVeyor and needs someone to fix it."
  end if ENV['APPVEYOR']
end

module RSpec
  module Support
    module Spec
      def self.setup_simplecov(&block)
        # Simplecov emits some ruby warnings when loaded, so silence them.
        old_verbose, $VERBOSE = $VERBOSE, false

        return if ENV['NO_COVERAGE'] || RUBY_VERSION < '1.9.3'
        return if RUBY_ENGINE != 'ruby' || RSpec::Support::OS.windows?

        # Don't load it when we're running a single isolated
        # test file rather than the whole suite.
        return if RSpec.configuration.files_to_run.one?

        require 'simplecov'
        start_simplecov(&block)
      rescue LoadError
        warn "Simplecov could not be loaded"
      ensure
        $VERBOSE = old_verbose
      end

      def self.start_simplecov(&block)
        SimpleCov.start do
          add_filter "./bundle/"
          add_filter "./tmp/"
          add_filter do |source_file|
            # Filter out `spec` directory except when it is under `lib`
            # (as is the case in rspec-support)
            source_file.filename.include?('/spec/') && !source_file.filename.include?('/lib/')
          end

          instance_eval(&block) if block
        end
      end
      private_class_method :start_simplecov
    end
  end
end
