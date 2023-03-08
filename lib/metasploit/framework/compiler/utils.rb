module Metasploit
  module Framework
    module Compiler
      module Utils

        # Returns the normalized C code (with headers).
        #
        # @param code [String] The C source code.
        # @param headers [Metasploit::Framework::Compiler::Headers::Win32]
        # @return [String] The normalized code.
        def self.normalize_code(code, headers)
          code = code.lines.map { |line|
            if line =~ /^\s*#include <([[:print:]]+)>$/
              h = headers.include("#{$1}")
              %Q|#{h}\n|
            else
              line
            end
          }.join

          code
        end

      end
    end
  end
end
