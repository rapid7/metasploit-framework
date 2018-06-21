require 'metasploit/framework/obfuscation/crandomizer/utility'

module Metasploit
  module Framework
    module Obfuscation
      module CRandomizer
        module CodeFactory

          class FakeFunctionCollection
            attr_accessor :functions
            attr_reader :max_functions

            def initialize(max_functions)
              @functions = []
              @max_functions = max_functions
              populate
              self
            end

            def each
              functions.each do |f|
                yield f
              end
            end

            def sample
              functions.sample
            end

            def to_s
              functions.join("\n")
            end

            def has_function_name?(name)
              functions.each do |f|
                if f.var.name == name
                  return true
                end
              end

              false
            end

            def empty?
              functions.empty?
            end

            private

            def populate
              max_functions.times do |i|
                func_name = "function#{i}"
                fake_function = Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory::FakeFunction.new(func_name)
                function_code = fake_function.generate_body
                stub_parser = Metasm::C::Parser.new
                stub_parser.allow_bad_c = true
                stub_parser.parse(function_code)
                functions.concat(stub_parser.toplevel.statements)
              end
            end
          end
        end
      end
    end
  end
end
