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

          # Number of allowed threads when threads are counted in `before(:suite)`
          EXPECTED_THREAD_COUNT_BEFORE_SUITE = 1
          # `caller` for all Thread.new calls
          LOG_PATHNAME = Pathname.new('log/metasploit/framework/spec/threads/suite.log')

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
                  thread_count = Thread.list.count

                  # check with if first so that error message can be constructed lazily
                  if thread_count > EXPECTED_THREAD_COUNT_BEFORE_SUITE
                    # LOG_PATHNAME may not exist if suite run without `rake spec`
                    if LOG_PATHNAME.exist?
                      log = LOG_PATHNAME.read()
                    else
                      log "Run `rake spec` to log where Thread.new is called."
                    end

                    raise RuntimeError,
                          "#{thread_count} #{'thread'.pluralize(thread_count)} exist(s) when " \
                          "only #{EXPECTED_THREAD_COUNT_BEFORE_SUITE} " \
                          "#{'thread'.pluralize(EXPECTED_THREAD_COUNT_BEFORE_SUITE)} expected before suite runs:\n" \
                          "#{log}"
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

              ENV['RUBYOPT'] = "-I#{load_pathname} -r#{threads_logger_pathname} #{ENV['RUBYOPT']}"
            end

            Rake::Task.define_task(spec: 'metasploit:framework:spec:threads:suite')

            Rake::Task.define_task()
          end
        end
      end
    end
  end
end