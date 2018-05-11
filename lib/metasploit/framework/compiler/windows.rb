require 'metasm'
require 'erb'
require 'metasploit/framework/compiler/utils'
require 'metasploit/framework/compiler/headers/windows'

module Metasploit
  module Framework
    module Compiler

      class Windows

        # Returns the binary of a compiled source.
        #
        # @param c_template [String] The C source code to compile.
        # @param type [Symbol] PE type, either :exe or :dll
        # @raise [NotImplementedError] If the type is not supported.
        # @return [String] The compiled code.
        def self.compile_c(c_template, type=:exe, cpu=Metasm::Ia32.new)
          headers = Compiler::Headers::Windows.new
          source_code = Compiler::Utils.normalize_code(c_template, headers)
          pe = Metasm::PE.compile_c(cpu, source_code)

          case type
          when :exe
            pe.encode
          when :dll
            pe.encode('dll')
          else
            raise NotImplementedError
          end
        end

        # Saves the compiled code as a file. This is basically a wrapper of #self.compile.
        #
        # @param out_file [String] The file path to save the binary as.
        # @param c_template [String] The C source code to compile.
        # @param type [Symbol] PE type, either :exe or :dll
        # @return [Integer] The number of bytes written.
        def self.compile_c_to_file(out_file, c_template, type=:exe)
          pe = self.compile(c_template, type)
          File.write(out_file, pe)
        end
      end

    end
  end
end