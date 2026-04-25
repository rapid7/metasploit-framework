require 'metasm'
require 'metasploit/framework/compiler/pe'

module Metasploit
  module Framework
    module Compiler

      class Custom

        def self.compile_c(c_template, type=:exe, cpu=Metasm::Ia32.new)
          return Pe.from_c(c_template)
          #raise NotImplementedError, "Other type than :exe is not supported." unless type == :exe
        end

      end
    end
  end
end
