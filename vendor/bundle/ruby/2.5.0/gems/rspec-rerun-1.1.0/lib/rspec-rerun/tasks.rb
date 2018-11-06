require 'rspec/core/rake_task'
require 'rspec-rerun/formatter'

module RSpec
  module Rerun
    module Tasks
      class << self
        def rspec_options(args, spec_files = nil)
          options = [
            spec_files,
            '--require', 'rspec-rerun/formatter',
            '--format', 'RSpec::Rerun::Formatter',
            *dot_rspec_options
          ].compact.flatten
          if args[:tag]
            options << '--tag'
            options << args[:tag]
          end
          options
        end

        def parse_args(args)
          options = args.extras

          # Error on multiple arguments
          if options.size > 1
            fail ArgumentError 'rspec-rerun can take an integer (retry_count) or options hash'
          else
            options = options[0]
          end

          # Handle if opts is just a retry_count integer
          options = if options.is_a? Hash
            options
          else
            { retry_count: options }
          end

          # Parse environment variables
          options[:pattern] ||= ENV['RSPEC_RERUN_PATTERN'] if ENV['RSPEC_RERUN_PATTERN']
          options[:tag] ||= ENV['RSPEC_RERUN_TAG'] if ENV['RSPEC_RERUN_TAG']
          options[:retry_count] ||= ENV['RSPEC_RERUN_RETRY_COUNT'] if ENV['RSPEC_RERUN_RETRY_COUNT']
          options[:verbose] = (ENV['RSPEC_RERUN_VERBOSE'] != 'false') if options[:verbose].nil?

          options
        end

        def failing_specs
          File.read(RSpec::Rerun::Formatter::FILENAME).split
        end

        def failed_count
          failing_specs.count
        end

        def failure_message
          "[#{Time.now}] Failed, #{failed_count} failure#{failed_count == 1 ? '' : 's'}"
        end

        def run(args)
          Rake::Task['rspec-rerun:run'].execute(args)
        end

        def rerun(args)
          Rake::Task['rspec-rerun:rerun'].execute(args)
        end

        private

        def dot_rspec_options
          dot_rspec_file = ['.rspec', File.expand_path('~/.rspec')].detect { |f| File.exist?(f) }
          options = if dot_rspec_file
            file_contents = File.read(dot_rspec_file)
            file_contents.split(/\n+/).map(&:shellsplit).flatten
          else
            []
          end
          options.concat ['--format', 'progress'] unless options.include?('--format')
          options
        end
      end
    end
  end
end

desc 'Run RSpec examples.'
RSpec::Core::RakeTask.new('rspec-rerun:run') do |t, args|
  t.pattern = args[:pattern] if args[:pattern]
  t.fail_on_error = false
  t.verbose = false if args[:verbose] == false
  t.rspec_opts = RSpec::Rerun::Tasks.rspec_options(args)
end

desc 'Re-run failed RSpec examples.'
RSpec::Core::RakeTask.new('rspec-rerun:rerun') do |t, args|
  failing_specs = RSpec::Rerun::Tasks.failing_specs

  t.pattern = 'deliberately-left-blank'
  t.fail_on_error = false
  t.verbose = false if args[:verbose] == false
  t.rspec_opts =  RSpec::Rerun::Tasks.rspec_options(args, failing_specs.join(' '))
end

desc 'Run RSpec code examples.'
task 'rspec-rerun:spec' do |_t, args|
  parsed_args = RSpec::Rerun::Tasks.parse_args(args)
  retry_count = (parsed_args[:retry_count] || 1).to_i

  fail 'retry count must be >= 1' if retry_count <= 0
  FileUtils.rm_f RSpec::Rerun::Formatter::FILENAME
  RSpec::Rerun::Tasks.run(parsed_args)

  until $?.success? || retry_count == 0
    retry_count -= 1
    msg = RSpec::Rerun::Tasks.failure_message
    msg += ", re-running, #{retry_count} #{retry_count == 1 ? 'retry' : 'retries'} left" if retry_count > 0
    $stderr.puts msg
    RSpec::Rerun::Tasks.rerun(parsed_args)
  end

  unless $?.success?
    $stderr.puts RSpec::Rerun::Tasks.failure_message
    failed_count = RSpec::Rerun::Tasks.failed_count
    fail "#{failed_count} failure#{failed_count == 1 ? '' : 's'}"
  end
end
