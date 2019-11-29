require 'msf/util/helper'
require 'open3'

module Metasploit
  module Framework
    module Compiler
      module Mingw
        MINGW_X86 = 'i686-w64-mingw32-gcc'
        MINGW_X64 = 'x86_64-w64-mingw32-gcc'

        INCLUDE_DIR = File.join(Msf::Config.install_root, 'data', 'headers', 'windows', 'c_payload_util')
        UTILITY_DIR = File.join(Msf::Config.install_root, 'data', 'utilities', 'encrypted_payload')

        def compile_c(src)
          cmd = build_cmd(src)

          stdin_err, status = Open3.capture2e(cmd)
          stdin_err
        end

        def build_cmd(src)
          cmd = ''
          link_options = '-Wl,'

          src_file = File.basename(self.file_name, '.exe')
          path = File.join(Msf::Config.install_root, "#{src_file}.c")
          File.write(path, src)

          opt_level = [ 'Os', 'O0', 'O1', 'O2', 'O3', 'Og' ].include?(self.opt_lvl) ? "-#{self.opt_lvl} " : "-O2 "

          cmd << "#{self.mingw_bin} "
          cmd << "#{path} -I #{INCLUDE_DIR} "
          cmd << "-o #{Msf::Config.install_root}/#{self.file_name} "

          # gives each function its own section
          # allowing them to be reordered
          cmd << '-ffunction-sections '
          cmd << '-fno-asynchronous-unwind-tables '
          cmd << '-nostdlib '
          cmd << '-fno-ident '
          cmd << opt_level

          link_options << '--no-seh,'
          link_options << '-s,' if self.strip_syms
          link_options << "-T#{self.link_script}" if self.link_script

          cmd << link_options

          cmd
        end

        def cleanup_files
          file_base = File.basename(self.file_name, '.exe')
          src_file = "#{file_base}.c"
          exe_file = "#{file_base}.exe"
          file_path = Msf::Config.install_root

          unless self.keep_src
            File.delete("#{file_path}/#{src_file}") if File.exist?("#{file_path}/#{src_file}")
          end

          unless self.keep_exe
            File.delete("#{file_path}/#{exe_file}") if File.exist?("#{file_path}/#{exe_file}")
          end
        rescue Errno::ENOENT
          print_error("Failed to delete file")
        end

        class X86
          include Mingw

          attr_reader :file_name, :keep_exe, :keep_src, :strip_syms, :link_script, :opt_lvl, :mingw_bin

          def initialize(opts={})
            @file_name = opts[:f_name]
            @keep_exe = opts[:keep_exe]
            @keep_src = opts[:keep_src]
            @strip_syms = opts[:strip_symbols]
            @link_script = opts[:linker_script]
            @opt_lvl = opts[:opt_lvl]
            @mingw_bin = MINGW_X86
          end

          def self.available?
            !!(Msf::Util::Helper.which(MINGW_X86))
          end
        end

        class X64
          include Mingw

          attr_reader :file_name, :keep_exe, :keep_src, :strip_syms, :link_script, :opt_lvl, :mingw_bin

          def initialize(opts={})
            @file_name = opts[:f_name]
            @keep_exe = opts[:keep_exe]
            @keep_src = opts[:keep_src]
            @strip_syms = opts[:strip_symbols]
            @link_script = opts[:linker_script]
            @opt_lvl = opts[:opt_lvl]
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
