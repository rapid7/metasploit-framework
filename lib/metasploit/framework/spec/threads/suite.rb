require 'pathname'

# @note needs to use explicit nesting. so this file can be loaded directly without loading 'metasploit/framework' which
#   allows for faster loading of rake tasks.
module Metasploit
  module Framework
    module Spec
      module Threads
        module Suite
          #
          # CONSTANTS
          #

          # Number of allowed threads when threads are counted in `after(:suite)` or `before(:suite)`
          EXPECTED_THREAD_COUNT_AROUND_SUITE = 2

          # `caller` for all Thread.new calls
          LOG_PATHNAME = Pathname.new('log/metasploit/framework/spec/threads/suite.log')
          # Regular expression for extracting the UUID out of {LOG_PATHNAME} for each Thread.new caller block
          UUID_REGEXP = /BEGIN Thread.new caller \((?<uuid>.*)\)/
          # Name of thread local variable that Thread UUID is stored
          UUID_THREAD_LOCAL_VARIABLE = "metasploit/framework/spec/threads/logger/uuid"

          #
          # Module Methods
          #

          # Configures `before(:suite)` and `after(:suite)` callback to detect thread leaks.
          #
          # @return [void]
          def self.configure!
            unless @configured
              RSpec.configure do |config|
                config.before(:suite) do
                  thread_count = Metasploit::Framework::Spec::Threads::Suite.non_debugger_thread_list.count

                  # check with if first so that error message can be constructed lazily
                  if thread_count > EXPECTED_THREAD_COUNT_AROUND_SUITE
                    # LOG_PATHNAME may not exist if suite run without `rake spec`
                    if LOG_PATHNAME.exist?
                      log = LOG_PATHNAME.read()
                    else
                      log "Run `rake spec` to log where Thread.new is called."
                    end

                    raise RuntimeError,
                          "#{thread_count} #{'thread'.pluralize(thread_count)} exist(s) when " \
                          "only #{EXPECTED_THREAD_COUNT_AROUND_SUITE} " \
                          "#{'thread'.pluralize(EXPECTED_THREAD_COUNT_AROUND_SUITE)} expected before suite runs:\n" \
                          "#{log}"
                  end

                  LOG_PATHNAME.parent.mkpath

                  LOG_PATHNAME.open('a') do |f|
                    # separator so after(:suite) can differentiate between threads created before(:suite) and during the
                    # suites
                    f.puts 'before(:suite)'
                  end
                end

                config.after(:suite) do
                  LOG_PATHNAME.parent.mkpath

                  LOG_PATHNAME.open('a') do |f|
                    # separator so that a flip flop can be used when reading the file below.  Also useful if it turns
                    # out any threads are being created after this callback, which could be the case if another
                    # after(:suite) accidentally created threads by creating an Msf::Simple::Framework instance.
                    f.puts 'after(:suite)'
                  end

                  thread_list = Metasploit::Framework::Spec::Threads::Suite.non_debugger_thread_list
                  thread_count = thread_list.count

                  if thread_count > EXPECTED_THREAD_COUNT_AROUND_SUITE
                    error_lines = []

                    if LOG_PATHNAME.exist?
                      caller_by_thread_uuid = Metasploit::Framework::Spec::Threads::Suite.caller_by_thread_uuid

                      thread_list.each do |thread|
                        thread_uuid = thread[Metasploit::Framework::Spec::Threads::Suite::UUID_THREAD_LOCAL_VARIABLE]

                        # unmanaged thread, such as the main VM thread
                        unless thread_uuid
                          next
                        end

                        caller = caller_by_thread_uuid[thread_uuid]

                        error_lines << "Thread #{thread_uuid}'s status is #{thread.status.inspect} " \
                                       "and was started here:\n"

                        error_lines.concat(caller)
                      end
                    else
                      error_lines << "Run `rake spec` to log where Thread.new is called."
                    end

                    raise RuntimeError,
                          "#{thread_count} #{'thread'.pluralize(thread_count)} exist(s) when only " \
                          "#{EXPECTED_THREAD_COUNT_AROUND_SUITE} " \
                          "#{'thread'.pluralize(EXPECTED_THREAD_COUNT_AROUND_SUITE)} expected after suite runs:\n" \
                          "#{error_lines.join}"
                  end
                end
              end

              @configured = true
            end

            @configured
          end

          def self.define_task
            Rake::Task.define_task('metasploit:framework:spec:threads:suite') do
              if Metasploit::Framework::Spec::Threads::Suite::LOG_PATHNAME.exist?
                Metasploit::Framework::Spec::Threads::Suite::LOG_PATHNAME.delete
              end

              parent_pathname = Pathname.new(__FILE__).parent
              threads_logger_pathname = parent_pathname.join('logger')
              load_pathname = parent_pathname.parent.parent.parent.parent.expand_path

              # Must append to RUBYOPT or Rubymine debugger will not work
              ENV['RUBYOPT'] = "#{ENV['RUBYOPT']} -I#{load_pathname} -r#{threads_logger_pathname}"
            end

            Rake::Task.define_task(spec: 'metasploit:framework:spec:threads:suite')
          end

          # @note Ensure {LOG_PATHNAME} exists before calling.
          #
          # Yields each line of {LOG_PATHNAME} that happened during the suite run.
          #
          # @yield [line]
          # @yieldparam line [String] a line in the {LOG_PATHNAME} between `before(:suite)` and `after(:suite)`
          # @yieldreturn [void]
          def self.each_suite_line
            in_suite = false

            LOG_PATHNAME.each_line do |line|
              if in_suite
                if line.start_with?('after(:suite)')
                  break
                else
                  yield line
                end
              else
                if line.start_with?('before(:suite)')
                  in_suite = true
                end
              end
            end
          end

          # @note Ensure {LOG_PATHNAME} exists before calling.
          #
          # Yield each line for each Thread UUID gathered during the suite run.
          #
          # @yield [uuid, line]
          # @yieldparam uuid [String] the UUID of thread thread
          # @yieldparam line [String] a line in the `caller` for the given `uuid`
          # @yieldreturn [void]
          def self.each_thread_line
            in_thread_caller = false
            uuid = nil

            each_suite_line do |line|
              if in_thread_caller
                if line.start_with?('END Thread.new caller')
                  in_thread_caller = false
                  next
                else
                  yield uuid, line
                end
              else
                match = line.match(UUID_REGEXP)

                if match
                  in_thread_caller = true
                  uuid = match[:uuid]
                end
              end
            end
          end

          # The `caller` for each Thread UUID.
          #
          # @return [Hash{String => Array<String>}]
          def self.caller_by_thread_uuid
            lines_by_thread_uuid = Hash.new { |hash, uuid|
              hash[uuid] = []
            }

            each_thread_line do |uuid, line|
              lines_by_thread_uuid[uuid] << line
            end

            lines_by_thread_uuid
          end

          # @return
          def self.non_debugger_thread_list
            Thread.list.reject { |thread|
              # don't do `is_a? Debugger::DebugThread` because it requires Debugger::DebugThread to be loaded, which it
              # won't when not debugging.
              thread.class.name == 'Debugger::DebugThread' ||
                thread.class.name == 'Debase::DebugThread'
            }
          end
        end
      end
    end
  end
end
