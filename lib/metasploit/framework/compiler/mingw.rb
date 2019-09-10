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

          # execute command -> get output
          system(cmd)
        end

        def self.build_cmd(src, opts={})
          cmd = ''
          link_options = '-Wl,'

          path = File.join(Msf::Config.install_root, 'payload.c')
          File.write(path, src)

          case opts[:arch]
          when 'x86'
            cmd << "#{MINGW_X86} "
          when 'x64'
            cmd << "#{MINGW_X64} "
          else
            # Not implemented
          end

          cmd << "#{path} -I #{INCLUDE_DIR} "
          cmd << "-o #{Msf::Config.install_root}/reverse_pic.exe "

          # gives each function its own section
          # allowing them to be reordered
          cmd << '-ffunction-sections '
          cmd << '-fno-asynchronous-unwind-tables '
          cmd << '-nostartfiles '
          cmd << '-fno-ident '
          cmd << '-O3 '

          # need to add object file to command
          # if arch is x64
          cmd << "#{opts[:align_obj]} " unless opts[:align_obj].empty?

          link_options << '--no-seh,'
          link_options << '-s,' if opts[:strip_symbols]
          link_options << "-T#{opts[:linker_script]}" if opts[:linker_script]

          cmd << link_options

          puts cmd
          cmd
        end
      end
    end
  end
end
