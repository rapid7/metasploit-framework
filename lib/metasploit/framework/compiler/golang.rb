require 'open3'
require 'fileutils'

module Metasploit
  module Framework
    module Compiler
      # Class for handling the go compiler
      class Golang

        UncompilablePayloadError = Class.new(StandardError)
        CompiledPayloadNotFoundError = Class.new(StandardError)
        GoModInitError = Class.new(StandardError)

        DefaultCompiler = 'go'.freeze

        attr_reader :outfile, :env, :ldflags, :compiler, :keep_src, :compiler_flags, :build_flags

        def initialize(**opts)
          @env = opts[:env]
          @compiler = opts[:compiler] || DefaultCompiler
          @compiler_flags = split(opts[:compiler_flags])
          @outfile = opts[:outfile]
          @build_flags = split(opts[:build_flags])
          @ldflags = opts[:ldflags]
          @keep_src = opts[:keep_src]
        end

        def self.available?
          !!Msf::Util::Helper.which(DefaultCompiler)
        end

        def go_build_src(src, *files)
          within_temp(files) do |dir, _fnames|
            Tempfile.create(['main_', "__#{File.basename(outfile)}.go"], dir) do |file|
              File.write(file, src)
              if keep_src
                src_copy = File.join(File.dirname(outfile), File.basename(file.path))
                FileUtils.cp(file, src_copy)
              end
              return src_copy, compile
            end
          end
        end

        def go_build_files(*files)
          within_temp(files) { compile }
        end

        def cmd_build
          cmd = [compiler]
          cmd << compiler_flags
          cmd << 'build'
          cmd << build_flags
          cmd << '-o'
          cmd << outfile
          if ldflags
            cmd << '-ldflags'
            cmd << "'#{ldflags}'"
          end
          cmd.flatten.compact
        end

        def compile
          mod_init
          exec(cmd_build)
        end

        def mod_init(pkgname = Rex::Text.rand_text_alphanumeric(8))
          err, status = Open3.capture2e(env, 'go', 'mod', 'init', pkgname)
          raise GoModInitError, err unless status.exitstatus == 0

          err, status = Open3.capture2e(env, 'go', 'mod', 'tidy')
          raise GoModInitError, err unless status.exitstatus == 0
        end

        def exec(cmd)
          stdout_err, status = Open3.capture2e(env, *cmd)
          raise UncompilablePayloadError, stdout_err unless status.exitstatus == 0

          stdout_err
        end

        private

        def within_temp(files)
          Dir.mktmpdir do |dir|
            Dir.chdir(dir) do
              files.map! do |file|
                FileUtils.cp(file, dir)
                File.basename(file)
              end
              yield(dir, files)
            end
          end
        end

        def split(opt)
          if opt
            opt.split(',')
          end
        end

      end
    end
  end
end
