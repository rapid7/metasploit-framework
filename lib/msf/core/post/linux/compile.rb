# -*- coding: binary -*-

module Msf
  class Post
    module Linux
      module Compile
        include ::Msf::Post::Common
        include ::Msf::Post::Linux::System
        include ::Msf::Post::File
        include ::Msf::Post::Unix

        def initialize(info = {})
          super
          register_options([
            OptEnum.new('COMPILE', [true, 'Compile on target', 'Auto', ['Auto', 'True', 'False']]),
            OptEnum.new('COMPILER', [true, 'Compiler to use on target', 'Auto', ['Auto', 'gcc', 'clang']]),
          ], self.class)
        end

        # Determines the available compiler on the target system.
        #
        # @return [String, nil] The name of the compiler ('gcc' or 'clang') if available, or nil if none are found.
        def get_compiler
          if has_gcc?
            return 'gcc'
          elsif has_clang?
            return 'clang'
          else
            return nil
          end
        end

        # Checks whether the target supports live compilation based on the module's configuration and available tools.
        #
        # @return [Boolean] True if compilation is supported and a compiler is available; otherwise, False.
        # @raise [Module::Failure::BadConfig] If the specified compiler is not installed and compilation is required.
        def live_compile?
          return false unless %w[Auto True].include?(datastore['COMPILE'])

          if datastore['COMPILER'] == 'gcc' && has_gcc?
            vprint_good 'gcc is installed'
            return true
          elsif datastore['COMPILER'] == 'clang' && has_clang?
            vprint_good 'clang is installed'
            return true
          elsif datastore['COMPILER'] == 'Auto' && get_compiler.present?
            return true
          end

          unless datastore['COMPILE'] == 'Auto'
            fail_with Module::Failure::BadConfig, "#{datastore['COMPILER']} is not installed. Set COMPILE False to upload a pre-compiled executable."
          end

          false
        end

        #
        # Uploads C code to the target, compiles it, and handles verification of the compiled binary.
        #
        # @param path [String] The path where the compiled binary will be created.
        # @param data [String] The C code to compile.
        # @param compiler_args [String] Additional arguments for the compiler command.
        # @raise [Module::Failure::BadConfig] If compilation fails or no compiler is found.
        #
        def upload_and_compile(path, data, compiler_args = '')
          compiler = datastore['COMPILER']
          if datastore['COMPILER'] == 'Auto'
            compiler = get_compiler
            fail_with(Module::Failure::BadConfig, 'Unable to find a compiler on the remote target.') if compiler.nil?
          end

          path = "#{path}.c" unless path.end_with?('.c')

          # only upload the file if a compiler exists
          write_file path.to_s, strip_comments(data)

          compiler_cmd = "#{compiler} -o '#{path.sub(/\.c$/, '')}' '#{path}'"
          if session.type == 'shell'
            compiler_cmd = "PATH=\"$PATH:/usr/bin/\" #{compiler_cmd}"
          end

          unless compiler_args.to_s.blank?
            compiler_cmd << " #{compiler_args}"
          end

          verification_token = Rex::Text.rand_text_alphanumeric(8)
          success = cmd_exec("#{compiler_cmd} && echo #{verification_token}")&.include?(verification_token)

          rm_f path.to_s

          unless success
            message = "#{path} failed to compile."
            # don't mention the COMPILE option if it was deregistered
            message << ' Set COMPILE to False to upload a pre-compiled executable.' if options.include?('COMPILE')
            fail_with Module::Failure::BadConfig, message
          end

          chmod path
        end

        #
        # Strips comments from C source code.
        #
        # @param c_code [String] The C source code.
        # @return [String] The C code with comments removed.
        #
        def strip_comments(c_code)
          c_code.gsub(%r{/\*.*?\*/}m, '').gsub(%r{^\s*//.*$}, '')
        end
      end
    end
  end
end
