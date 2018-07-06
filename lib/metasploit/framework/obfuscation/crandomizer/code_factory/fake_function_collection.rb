require 'metasploit/framework/obfuscation/crandomizer/utility'

module Metasploit
  module Framework
    module Obfuscation
      module CRandomizer
        module CodeFactory

          class FakeFunctionCollection
            attr_accessor :functions
            attr_reader :max_functions

            # Initializes a Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory::FakeFunctionCollection instance.
            #
            # @param max_functions [Integer] Max number of fake functions to generate.
            # @return [Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory::FakeFunctionCollection]
            def initialize(max_functions)
              @functions = []
              @max_functions = max_functions
              populate
              self
            end

            # Yields a list of fake functions available.
            def each
              functions.each do |f|
                yield f
              end
            end

            # Returns a fake Metasm::C::Declaration from the FakeFunctionCollection object.
            #
            # @return [Metasm::C::Declaration]
            def sample
              functions.sample
            end

            # Returns a string that joins the fake functions
            def to_s
              functions.join("\n")
            end

            # Asks the FakeFunctionCollection if a function is available.
            #
            # @param name [String]
            # @return [Boolean]
            def has_function_name?(name)
              functions.each do |f|
                if f.var.name == name
                  return true
                end
              end

              false
            end

            # Checks if the collection is empty or not.
            def empty?
              functions.empty?
            end

            private

            # Generates a list of fake functions to use.
            def populate
              max_functions.times do |i|
                func_name = "function#{i}"
                fake_function = Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory::FakeFunction.new(func_name)
                function_code = fake_function.generate_body
                stub_parser = Metasploit::Framework::Obfuscation::CRandomizer::Utility.parse(function_code)
                functions.concat(stub_parser.toplevel.statements)
              end
            end
          end
        end
      end
    end
  end
end
