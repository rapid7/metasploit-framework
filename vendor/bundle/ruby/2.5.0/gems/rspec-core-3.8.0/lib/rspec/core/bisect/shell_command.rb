RSpec::Support.require_rspec_core "shell_escape"
require 'shellwords'

module RSpec
  module Core
    module Bisect
      # Provides an API to generate shell commands to run the suite for a
      # set of locations, using the given bisect server to capture the results.
      # @private
      class ShellCommand
        attr_reader :original_cli_args

        def initialize(original_cli_args)
          @original_cli_args = original_cli_args.reject { |arg| arg.start_with?("--bisect") }
        end

        def command_for(locations, server)
          parts = []

          parts << RUBY << load_path
          parts << open3_safe_escape(RSpec::Core.path_to_executable)

          parts << "--format"   << "bisect-drb"
          parts << "--drb-port" << server.drb_port

          parts.concat(reusable_cli_options)
          parts.concat(locations.map { |l| open3_safe_escape(l) })

          parts.join(" ")
        end

        def repro_command_from(locations)
          parts = []

          parts.concat environment_repro_parts
          parts << "rspec"
          parts.concat Formatters::Helpers.organize_ids(locations)
          parts.concat original_cli_args_without_locations

          parts.join(" ")
        end

        def original_locations
          parsed_original_cli_options.fetch(:files_or_directories_to_run)
        end

        def bisect_environment_hash
          if ENV.key?('SPEC_OPTS')
            { 'SPEC_OPTS' => spec_opts_without_bisect }
          else
            {}
          end
        end

        def spec_opts_without_bisect
          Shellwords.join(
            Shellwords.split(ENV.fetch('SPEC_OPTS', '')).reject do |arg|
              arg =~ /^--bisect/
            end
          )
        end

      private

        include RSpec::Core::ShellEscape
        # On JRuby, Open3.popen3 does not handle shellescaped args properly:
        # https://github.com/jruby/jruby/issues/2767
        if RSpec::Support::Ruby.jruby?
          # :nocov:
          alias open3_safe_escape quote
          # :nocov:
        else
          alias open3_safe_escape escape
        end

        def environment_repro_parts
          bisect_environment_hash.map do |k, v|
            %Q(#{k}="#{v}")
          end
        end

        def reusable_cli_options
          @reusable_cli_options ||= begin
            opts = original_cli_args_without_locations

            if (port = parsed_original_cli_options[:drb_port])
              opts -= %W[ --drb-port #{port} ]
            end

            parsed_original_cli_options.fetch(:formatters) { [] }.each do |(name, out)|
              opts -= %W[ --format #{name} -f -f#{name} ]
              opts -= %W[ --out #{out} -o -o#{out} ]
            end

            opts
          end
        end

        def original_cli_args_without_locations
          @original_cli_args_without_locations ||= begin
            files_or_dirs = parsed_original_cli_options.fetch(:files_or_directories_to_run)
            @original_cli_args - files_or_dirs
          end
        end

        def parsed_original_cli_options
          @parsed_original_cli_options ||= Parser.parse(@original_cli_args)
        end

        def load_path
          @load_path ||= "-I#{$LOAD_PATH.map { |p| open3_safe_escape(p) }.join(':')}"
        end

        # Path to the currently running Ruby executable, borrowed from Rake:
        # https://github.com/ruby/rake/blob/v10.4.2/lib/rake/file_utils.rb#L8-L12
        # Note that we skip `ENV['RUBY']` because we don't have to deal with running
        # RSpec from within a MRI source repository:
        # https://github.com/ruby/rake/commit/968682759b3b65e42748cd2befb2ff3e982272d9
        RUBY = File.join(
          RbConfig::CONFIG['bindir'],
          RbConfig::CONFIG['ruby_install_name'] + RbConfig::CONFIG['EXEEXT']).
          sub(/.*\s.*/m, '"\&"')
      end
    end
  end
end
