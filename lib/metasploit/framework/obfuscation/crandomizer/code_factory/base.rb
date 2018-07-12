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
              @dep = []
              @code = normalized_stub
            end

            # Override this method when you inherit this class.
            # The method should return the source of the stub you're trying to create,
            # as a C function.
            # For example:
            # %Q|
            # void printf(const char*);
            # void stub() {
            #   printf("hello world\n");
            # }|
            # Notice if you are using a function like the above, you must declare/define that
            # beforehand. The function declaration will not be used in the final source code.
            def stub
              raise NotImplementedError
            end

            # Checks whether this class is suitable for the code.
            #
            # @param parser [Metasm::C::Parser]
            # @return [Boolean]
            def good_dep?(parser)
              # The difference between @dep and parser.toplevel.symbol.keys
              # is the list of functions not being supported by the original code.
              ready_function_names = parser.toplevel.symbol.keys
              delta = dep - ready_function_names
              if delta.empty?
                true
              else
                false
              end
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