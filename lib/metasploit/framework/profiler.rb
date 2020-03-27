require 'pathname'
require 'tmpdir'

module Metasploit
  module Framework
    module Profiler
      class << self
        def start
          return unless record_cpu? || record_memory?

          if record_cpu?
            require 'ruby-prof'

            dump_path = generate_path('cpu')
            profile = RubyProf::Profile.new

            profile.start

            at_exit do
              record_cpu(dump_path, profile)
            end
          end

          if record_memory?
            require 'memory_profiler'
            require 'rex/compat'

            report_path = generate_path( "memory.profile")

            MemoryProfiler.start

            at_exit do
              puts "Generating memory report #{report_path}"
              report = MemoryProfiler.stop

              if report.nil?
                puts 'Report was not successfully generated. This can happen when "record_memory" is called in '\
                'combination with the "METASPLOIT_MEMORY_PROFILE" environment variable being set.'
              end
              report.pretty_print(to_file: report_path)
              Rex::Compat.open_file(report_path)
            end
          end
        end

        def record_cpu(path=generate_path('dev_cpu'), profile= RubyProf::Profile.new, &block)
          require 'ruby-prof'
          require 'rex/compat'

          ::FileUtils.mkdir_p(path)

          profile.start unless profile.running?
          block.call if block_given?

          puts "Generating CPU dump #{path}"
          result = profile.stop

          printer = RubyProf::MultiPrinter.new(result, %i[flat graph_html tree stack])
          printer.print(path: path)

          Rex::Compat.open_file(path)
        end

        def record_memory(path=generate_path('dev_memory.profile'), &block)
          require 'memory_profiler'
          require 'rex/compat'

          MemoryProfiler.start
          block.call

          puts "Generating memory report #{path}"
          report = MemoryProfiler.stop

          report.pretty_print(to_file: path)
          Rex::Compat.open_file(path)
        end

        def generate_path(file_name)
          tmp_directory = Dir.mktmpdir("msf-profile-#{Time.now.strftime('%Y%m%d%H%M%S')}")
          Pathname.new(tmp_directory).join(file_name)
        end

        private
        def record_cpu?
          ENV['METASPLOIT_CPU_PROFILE']
        end

        def record_memory?
          ENV['METASPLOIT_MEMORY_PROFILE']
        end
      end
    end
  end
end
