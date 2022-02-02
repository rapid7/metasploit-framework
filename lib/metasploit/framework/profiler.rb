# frozen_string_literal: true

require 'pathname'
require 'tmpdir'

module Metasploit
  module Framework
    module Profiler
      class << self
        def start
          return unless record_global_cpu? || record_global_memory?
          raise 'Cannot profile memory and cpu at the same time' if record_global_cpu? && record_global_memory?

          if record_global_cpu?
            require 'ruby-prof'

            results_path = tmp_cpu_results_path
            profile = RubyProf::Profile.new
            profile.start

            at_exit do
              result = profile.stop
              save_cpu_result(result, path: results_path)
            end
          end

          if record_global_memory?
            require 'memory_profiler'

            results_path = tmp_memory_results_path
            profile = MemoryProfiler
            profile.start

            at_exit do
              puts "Generating memory dump #{results_path}"
              result = profile.stop
              save_memory_result(result, path: results_path)
            end
          end
        end

        def record_cpu
          require 'ruby-prof'

          results_path = tmp_cpu_results_path
          profile = RubyProf::Profile.new
          profile.start

          yield

          result = profile.stop
          save_cpu_result(result, path: results_path)
        end

        def record_memory
          raise 'Cannot mix global memory recording and localised memory recording' if record_global_memory?

          require 'memory_profiler'

          results_path = tmp_memory_results_path
          profile = MemoryProfiler
          profile.start

          yield

          result = profile.stop
          save_memory_result(result, path: results_path)
        end

        private

        def record_global_cpu?
          ENV['METASPLOIT_CPU_PROFILE']
        end

        def record_global_memory?
          ENV['METASPLOIT_MEMORY_PROFILE']
        end

        def tmp_path_for(name:)
          tmp_directory = Dir.mktmpdir("msf-profile-#{Time.now.strftime('%Y%m%d%H%M%S')}")
          Pathname.new(tmp_directory).join(name)
        end

        def tmp_cpu_results_path
          path = tmp_path_for(name: 'cpu')
          ::FileUtils.mkdir_p(path)
          path
        end

        def tmp_memory_results_path
          tmp_path_for(name: 'memory')
        end

        def save_cpu_result(result, path:)
          require 'rex/compat'

          puts "Generating CPU dump #{path}"

          printer = RubyProf::MultiPrinter.new(result, %i[flat graph_html tree stack])
          printer.print(path: path)

          Rex::Compat.open_file(path)
        end

        def save_memory_result(result, path:)
          require 'rex/compat'

          result.pretty_print(to_file: path)
          Rex::Compat.open_file(path)
        end
      end
    end
  end
end
