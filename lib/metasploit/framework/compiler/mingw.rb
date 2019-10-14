require 'msf/util/helper'

module Metasploit
  module Framework
    module Compiler
      module Mingw

        MINGW_X86 = 'i686-w64-mingw32-gcc'
        MINGW_X64 = 'x86_64-w64-mingw32-gcc'

        INCLUDE_DIR = File.join(Msf::Config.install_root, 'data', 'headers', 'windows', 'c_payload_util')
        UTILITY_DIR = File.join(Msf::Config.install_root, 'data', 'utilities', 'encrypted_payload')

        def self.mingw_available?
          !!(Msf::Util::Helper.which(MINGW_X86) || Msf::Util::Helper.which(MINGW_X64))
        end

        def self.mingw_x86
          Msf::Util::Helper.which(MINGW_X86)
        end

        def self.mingw_x64
          Msf::Util::Helper.which(MINGW_X64)
        end

        def self.compile_c(src, opts={})
          cmd = self.build_cmd(src, opts)

          system(cmd)
        end

        def self.build_cmd(src, opts={})
          cmd = ''
          link_options = '-Wl,'

          src_file = opts[:f_name].split('.').first
          path = File.join(Msf::Config.install_root, "#{src_file}.c")
          File.write(path, src)

          opt_level = [ 'Os', 'O1', 'O2', 'O3' ].include?(opts[:opt_lvl]) ? "-#{opts[:opt_lvl]} " : "-O2 "

          case opts[:arch]
          when 'x86'
            cmd << "#{MINGW_X86} "
          when 'x64'
            cmd << "#{MINGW_X64} "
          else
            return print_error('Unsupported architecture')
          end

          cmd << "#{path} -I #{INCLUDE_DIR} "
          cmd << "-o #{Msf::Config.install_root}/#{opts[:f_name]} "

          # gives each function its own section
          # allowing them to be reordered
          cmd << '-ffunction-sections '
          cmd << '-fno-asynchronous-unwind-tables '
          cmd << '-nostartfiles '
          cmd << '-fno-ident '
          cmd << opt_level

          cmd << "#{opts[:align_obj]} " unless opts[:align_obj].empty?

          link_options << '--no-seh,'
          link_options << '-s,' if opts[:strip_symbols]
          link_options << "-T#{opts[:linker_script]}" if opts[:linker_script]

          cmd << link_options

          cmd
        end

        def self.cleanup_files(opts={})
          file_base = opts[:f_name].split('.').first
          src_file = "#{file_base}.c"
          exe_file = "#{file_base}.exe"
          file_path = Msf::Config.install_root

          unless opts[:keep_src]
            File.delete("#{file_path}/#{src_file}") if File.exist?("#{file_path}/#{src_file}")
          end

          unless opts[:keep_exe]
            File.delete("#{file_path}/#{exe_file}") if File.exist?("#{file_path}/#{exe_file}")
          end
        rescue Errno::ENOENT
          print_error("Failed to delete file")
        end
      end
    end
  end
end
