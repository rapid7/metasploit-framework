require 'pathname'
require 'tmpdir'

module Metasploit
  module Framework
    module Profiler
      class << self
        def start
          return unless record_cpu? || record_memory?

          timestamp = Time.now.strftime('%Y%m%d%H%M%S')
          tmp_directory = Dir.mktmpdir("msf-profile-#{timestamp}")
          tmp_path = Pathname.new(tmp_directory)

          if record_cpu?
            require 'ruby-prof'
            require 'rex/compat'

            dump_path = tmp_path.join("cpu")
            ::FileUtils.mkdir_p(dump_path)

            RubyProf.start

            at_exit do
              puts "Generating CPU dump #{dump_path}"
              result = RubyProf.stop
              printer = RubyProf::MultiPrinter.new(result, %i[flat graph_html tree stack])
              printer.print(path: dump_path)

              Rex::Compat.open_file(dump_path)
            end
          end

          if record_memory?
            require 'memory_profiler'
            require 'rex/compat'

            report_name = "memory.profile"
            report_path = tmp_path.join(report_name)

            MemoryProfiler.start

            at_exit do
              puts "Generating memory report #{dump_path}"
              report = MemoryProfiler.stop
              report.pretty_print(to_file: report_path)

              puts "Memory report saved to #{report_path}"
              Rex::Compat.open_file(report_path)
            end
          end
        end

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
