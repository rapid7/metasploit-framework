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
            if line =~ /^#include <([[:print:]]+)>$/
              %Q|<%= headers.include('#{$1}') %>\n|
            else
              line
            end
          }.join

          ERB.new(code).result(binding)
        end

      end
    end
  end
end