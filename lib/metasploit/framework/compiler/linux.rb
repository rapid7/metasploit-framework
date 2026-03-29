require 'open3'
require 'tmpdir'

module Metasploit
  module Framework
    module Compiler

      # Compiles C source code into native Linux ELF binaries using GCC.
      # Mirrors the interface of Metasploit::Framework::Compiler::Windows.
      class Linux

        GCC_X64     = 'gcc'
        GCC_X86     = 'gcc'
        GCC_AARCH64 = 'aarch64-linux-gnu-gcc'

        # Path to Linux-specific bundled headers (e.g. rc4.h).
        HEADERS_DIR = File.join(Msf::Config.data_directory, 'headers', 'linux')

        # Compiles a C source string into a Linux ELF binary.
        #
        # @param c_template [String] C source code to compile.
        # @param arch [Symbol]  Target architecture: :x64, :x86, or :aarch64.
        # @param opts [Hash]
        # @option opts [Boolean] :strip    Strip debug symbols (default: true).
        # @option opts [String]  :extra_flags  Additional flags passed to GCC.
        # @raise [CompilationError] if the required GCC toolchain is missing or
        #   compilation fails.
        # @return [String] Raw bytes of the compiled ELF binary.
        def self.compile_c(c_template, arch = :x64, opts = {})
          gcc = gcc_binary(arch)

          unless available?(arch)
            raise CompilationError,
                  "GCC for #{arch} not found ('#{gcc}'). " \
                  'Install the required toolchain with your package manager.'
          end

          Dir.mktmpdir('msf_linux_compiler') do |tmpdir|
            src_file = File.join(tmpdir, 'payload.c')
            out_file = File.join(tmpdir, 'payload')

            File.write(src_file, c_template)

            cmd = build_cmd(gcc, arch_flag(arch), src_file, out_file, opts)
            output, status = Open3.capture2e(cmd)

            unless status.success?
              raise CompilationError, "GCC compilation failed:\n#{output}"
            end

            unless File.exist?(out_file)
              raise CompilationError, 'Compiled binary not found after GCC run'
            end

            File.binread(out_file)
          end
        end

        # Returns whether the required GCC toolchain for the given arch is on PATH.
        #
        # @param arch [Symbol] :x64, :x86, or :aarch64.
        # @return [Boolean]
        def self.available?(arch = :x64)
          !Msf::Util::Helper.which(gcc_binary(arch)).nil?
        end

        class CompilationError < StandardError; end

        private_class_method def self.gcc_binary(arch)
          case arch
          when :x64     then GCC_X64
          when :x86     then GCC_X86
          when :aarch64 then GCC_AARCH64
          else raise ArgumentError, "Unsupported arch: #{arch}"
          end
        end

        private_class_method def self.arch_flag(arch)
          case arch
          when :x64     then '-m64'
          when :x86     then '-m32'
          when :aarch64 then ''
          else ''
          end
        end

        private_class_method def self.build_cmd(gcc, arch_flag, src_file, out_file, opts = {})
          strip       = opts.fetch(:strip, true)
          extra_flags = opts[:extra_flags].to_s

          cmd  = "#{gcc} #{arch_flag} #{src_file}"
          cmd << " -I #{HEADERS_DIR}"
          cmd << " -o #{out_file}"
          cmd << ' -z execstack'
          cmd << ' -fno-stack-protector'
          cmd << ' -no-pie'
          cmd << ' -s' if strip
          cmd << " #{extra_flags}" unless extra_flags.empty?
          cmd
        end
      end

    end
  end
end
