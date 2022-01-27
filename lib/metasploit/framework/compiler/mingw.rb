require 'open3'
module Metasploit
  module Framework
    module Compiler
      module Mingw
        MINGW_X86 = 'i686-w64-mingw32-gcc'.freeze
        MINGW_X64 = 'x86_64-w64-mingw32-gcc'.freeze

        INCLUDE_DIR = File.join(Msf::Config.data_directory, 'headers', 'windows', 'c_payload_util')
        UTILITY_DIR = File.join(Msf::Config.data_directory, 'utilities', 'encrypted_payload')
        OPTIMIZATION_FLAGS = [ 'Os', 'O0', 'O1', 'O2', 'O3', 'Og' ].freeze

        UncompilablePayloadError = Class.new(StandardError)
        CompiledPayloadNotFoundError = Class.new(StandardError)

        def compile_c(src)
          cmd = build_cmd(src)

          if show_compile_cmd
            print("#{cmd}\n")
          end

          stdin_err, status = Open3.capture2e(cmd)
          cleanup_files
          stdin_err
        end

        def build_cmd(src)
          src_file = "#{file_name}.c"
          exe_file = "#{file_name}.exe"

          cmd = ''
          link_options = '-Wl,'

          File.write(src_file, src)

          opt_level = OPTIMIZATION_FLAGS.include?(opt_lvl) ? "-#{opt_lvl} " : '-O2 '

          cmd << "#{mingw_bin} "
          cmd << "#{src_file} -I #{INCLUDE_DIR} "
          cmd << "-o #{exe_file} "

          # gives each function its own section
          # allowing them to be reordered
          cmd << '-ffunction-sections '
          cmd << '-fno-asynchronous-unwind-tables '
          cmd << '-fno-ident '
          cmd << opt_level

          if compile_options
            cmd << compile_options
          else
            link_options << '--image-base=0x0,'
            cmd << '-nostdlib '
          end

          link_options << '--no-seh'
          link_options << ',-s' if strip_syms
          link_options << ",-T #{link_script}" if link_script

          cmd << link_options
          cmd
        end

        def compile_cpp(src, *additional_files)
          within_temp(additional_files) do |dir, fnames|
            file = Tempfile.create(['', '.cpp'], dir)
            File.write(file, src)
            if keep_src
              dest = File.join(File.dirname(outfile), File.basename(file.path))
              FileUtils.cp(file, dest)
            end
            fnames << file.path
            cmd = build_cpp_files_cmd(fnames)
            return exec(cmd), dest
          end
        end

        def compile_cpp_files(files)
          within_temp(files) do |_dir, fnames|
            cmd = build_cpp_files_cmd(fnames)
            exec(cmd)
          end
        end

        def compile_cpp_file(file)
          compile_cpp_files([file])
        end

        def build_cpp_files_cmd(file_array)
          cmd = [ mingw_bin ]
          cmd << file_array
          cmd << '-I'
          cmd << INCLUDE_DIR
          cmd << '-o'
          cmd << outfile
          cmd << '-shared' if outfile.ends_with?('.dll')
          cmd << opt_lvl if OPTIMIZATION_FLAGS.include?(opt_lvl)
          cmd << compile_options

          if link_options
            link_opts = ['-Wl']
            link_opts << '-s' if strip_syms
            link_opts << link_options
            cmd << link_opts.join(',')
          end

          if link_script
            cmd << '-T'
            cmd << link_script
          end
          cmd.flatten
        end

        def exec(cmd)
          print("#{cmd.flatten.join(' ')}\n") if show_compile_cmd
          stdout_err, status = Open3.capture2e(*cmd)
          if status.exitstatus != 0
            raise UncompilablePayloadError, stdout_err
          end
          stdout_err
        end

        def cleanup_files(files = [])
          unless keep_src
            src_file = "#{file_name}.c"
            files << src_file
          end

          unless keep_exe
            exe_file = "#{file_name}.exe"
            files << exe_file
          end

          files.each do |file|
            File.delete(file) if File.exist?(file)
          end
        rescue Errno::ENOENT
          print_error('Failed to delete file')
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

        class X86
          include Mingw

          attr_reader :file_name, :keep_exe, :keep_src, :strip_syms, :link_script, :opt_lvl, :compile_options, :show_compile_cmd, :outfile, :link_options
          attr_accessor :mingw_bin

          def initialize(opts = {})
            @file_name = opts[:f_name]
            @outfile = opts[:outfile]
            @keep_exe = opts[:keep_exe]
            @keep_src = opts[:keep_src]
            @strip_syms = opts[:strip_symbols]
            @show_compile_cmd = opts[:show_compile_cmd]
            @link_script = opts[:linker_script]
            @compile_options = opts[:compile_options]
            @link_options = opts[:link_options]
            @opt_lvl = opts[:opt_lvl]
            @mingw_bin = opts[:mingw_bin] || MINGW_X86
          end

          def self.available?
            !!Msf::Util::Helper.which(MINGW_X86)
          end
        end

        class X64
          include Mingw

          attr_reader :file_name, :keep_exe, :keep_src, :strip_syms, :link_script, :opt_lvl, :compile_options, :show_compile_cmd, :outfile, :link_options
          attr_accessor :mingw_bin

          def initialize(opts = {})
            @file_name = opts[:f_name]
            @outfile = opts[:outfile]
            @keep_exe = opts[:keep_exe]
            @keep_src = opts[:keep_src]
            @strip_syms = opts[:strip_symbols]
            @show_compile_cmd = opts[:show_compile_cmd]
            @link_script = opts[:linker_script]
            @compile_options = opts[:compile_options]
            @link_options = opts[:link_options]
            @opt_lvl = opts[:opt_lvl]
            @mingw_bin = opts[:mingw_bin] || MINGW_X64
          end

          def self.available?
            !!Msf::Util::Helper.which(MINGW_X64)
          end
        end
      end
    end
  end
end
