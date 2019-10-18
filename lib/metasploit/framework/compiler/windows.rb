require 'metasm'
require 'erb'
require 'metasploit/framework/compiler/utils'
require 'metasploit/framework/compiler/headers/windows'
require 'metasploit/framework/obfuscation/crandomizer'

module Metasploit
  module Framework
    module Compiler

      class Windows

        # Returns the binary of a compiled source.
        #
        # @param c_template [String] The C source code to compile.
        # @param type [Symbol] PE type, either :exe or :dll
        # @param cpu [Metasm::CPU] A Metasm cpu object, for example: Metasm::Ia32.new
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
        # @param cpu [Metasm::CPU] A Metasm cpu object, for example: Metasm::Ia32.new
        # @return [Integer] The number of bytes written.
        def self.compile_c_to_file(out_file, c_template, type=:exe, cpu=Metasm::Ia32.new)
          pe = self.compile_c(c_template, type)
          File.write(out_file, pe)
        end

        # Returns randomized c source code.
        #
        # @param c_template [String]
        # 
        # @raise [NotImplementedError] If the type is not supported.
        # @return [String] The compiled code.
        def self.generate_random_c(c_template, opts={})
          weight = opts[:weight] || 80
          headers = Compiler::Headers::Windows.new
          source_code = Compiler::Utils.normalize_code(c_template, headers)

          randomizer = Metasploit::Framework::Obfuscation::CRandomizer::Parser.new(weight)
          randomized_code = randomizer.parse(source_code)
          randomized_code.to_s
        end

        # Returns the binary of a randomized and compiled source code.
        #
        # @param c_template [String]
        # 
        # @raise [NotImplementedError] If the type is not supported.
        # @return [String] The compiled code.
        def self.compile_random_c(c_template, opts={})
          type = opts[:type] || :exe
          cpu = opts[:cpu] || Metasm::Ia32.new

          random_c = self.generate_random_c(c_template, opts)
          self.compile_c(random_c, type, cpu)
        end

        # Saves the randomized compiled code as a file. This is basically a wrapper for #self.compile_random_c
        #
        # @param out_file [String] The file path to save the binary as.
        # @param c_template [String] The randomized C source code to compile.
        # @param opts [Hash] Options to pass to #compile_random_c
        # @return [Integer] The number of bytes written.
        def self.compile_random_c_to_file(out_file, c_template, opts={})
          pe = self.compile_random_c(c_template, opts)
          File.write(out_file, pe)
        end
      end

    end
  end
end
