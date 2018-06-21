require 'metasploit/framework/obfuscation/crandomizer/utility'

module Metasploit
  module Framework
    module Obfuscation
      module CRandomizer
        module CodeFactory

          class Base
            attr_reader :dep
            attr_reader :code

            def initialize
              @dep = ''
              @code = normalized_stub
            end

            def stub
              raise NotImplementedError
            end

            def normalized_stub
              stub_parser = Metasploit::Framework::Obfuscation::CRandomizer::Utility.parse(stub)
              stub_parser.toplevel.statements.last.var.initializer.statements
            end
          end

        end
      end
    end
  end
end