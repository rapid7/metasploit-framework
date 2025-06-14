require 'open3'
module Metasploit
  module Framework
    module Compiler
      module Mingw
        MINGW_X86 = 'i686-w64-mingw32-gcc'
        MINGW_X64 = 'x86_64-w64-mingw32-gcc'

        INCLUDE_DIR = File.join(Msf::Config.data_directory, 'headers', 'windows', 'c_payload_util')
        UTILITY_DIR = File.join(Msf::Config.data_directory, 'utilities', 'encrypted_payload')
        OPTIMIZATION_FLAGS = [ 'Os', 'O0', 'O1', 'O2', 'O3', 'Og' ]

        def compile_c(src)
          cmd = build_cmd(src)

          if self.show_compile_cmd
            print("#{cmd}\n")
          end

          stdin_err, status = Open3.capture2e(cmd)
          stdin_err
        end

        def build_cmd(src)
          src_file = "#{self.file_name}.c"
          exe_file = "#{self.file_name}.exe"

          cmd = ''
          link_options = '-Wl,'

          File.write(src_file, src)

          opt_level = OPTIMIZATION_FLAGS.include?(self.opt_lvl) ? "-#{self.opt_lvl} " : "-O2 "

          cmd << "#{self.mingw_bin} "
          cmd << "#{src_file} -I #{INCLUDE_DIR} "
          cmd << "#{self.include_dirs.map { |include_dir| "-iquote #{include_dir}" }.join(' ')} " if self.include_dirs.any?
          cmd << "-o #{exe_file} "

          # gives each function its own section
          # allowing them to be reordered
          cmd << '-ffunction-sections '
          cmd << '-fno-asynchronous-unwind-tables '
          cmd << '-fno-ident '
          cmd << opt_level

          if self.compile_options
            cmd << self.compile_options
          else
            link_options << '--image-base=0x0,'
            cmd << '-nostdlib '
          end

          link_options << '--no-seh'
          link_options << ',-s' if self.strip_syms
          link_options << ",-T#{self.link_script}" if self.link_script

          cmd << link_options

          cmd
        end

        def cleanup_files
          src_file = "#{self.file_name}.c"
          exe_file = "#{self.file_name}.exe"

          unless self.keep_src
            File.delete(src_file) if File.exist?(src_file)
          end

          unless self.keep_exe
            File.delete(exe_file) if File.exist?(exe_file)
          end
        rescue Errno::ENOENT
          print_error("Failed to delete file")
        end

        class X86
          include Mingw

          attr_reader :file_name, :keep_exe, :keep_src, :strip_syms, :link_script, :opt_lvl, :mingw_bin, :compile_options, :show_compile_cmd, :include_dirs

          def initialize(opts={})
            @file_name = opts[:f_name]
            @keep_exe = opts[:keep_exe]
            @keep_src = opts[:keep_src]
            @strip_syms = opts[:strip_symbols]
            @show_compile_cmd = opts[:show_compile_cmd]
            @link_script = opts[:linker_script]
            @compile_options = opts[:compile_options]
            @opt_lvl = opts[:opt_lvl]
            @include_dirs = opts[:include_dirs] || []
            @mingw_bin = MINGW_X86
          end

          def self.available?
            !!(Msf::Util::Helper.which(MINGW_X86))
          end
        end

        class X64
          include Mingw

          attr_reader :file_name, :keep_exe, :keep_src, :strip_syms, :link_script, :opt_lvl, :mingw_bin, :compile_options, :show_compile_cmd, :include_dirs

          def initialize(opts={})
            @file_name = opts[:f_name]
            @keep_exe = opts[:keep_exe]
            @keep_src = opts[:keep_src]
            @strip_syms = opts[:strip_symbols]
            @show_compile_cmd = opts[:show_compile_cmd]
            @link_script = opts[:linker_script]
            @compile_options = opts[:compile_options]
            @opt_lvl = opts[:opt_lvl]
            @include_dirs = opts[:include_dirs] || []
            @mingw_bin = MINGW_X64
          end

          def self.available?
            !!(Msf::Util::Helper.which(MINGW_X64))
          end
        end

        class UncompilablePayloadError < StandardError
          def initialize(msg='')
            super(msg)
          end
        end

        class CompiledPayloadNotFoundError < StandardError
          def initialize(msg='Compiled executable not found')
            super(msg)
          end
        end
      end
    end
  end
end
