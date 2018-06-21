require 'metasploit/framework/obfuscation/crandomizer/utility'
require 'metasploit/framework/obfuscation/crandomizer/modifier'

module Metasploit
  module Framework
    module Obfuscation
      module CRandomizer

        class Parser
          attr_accessor :max_random_weight
          attr_accessor :fake_functions_collection

          def initialize(weight, fake_functions)
            @max_random_weight = weight
            @fake_functions_collection = fake_functions
          end

          def parse(template)
            modifier = Metasploit::Framework::Obfuscation::CRandomizer::Modifier.new(fake_functions_collection, max_random_weight)

            main_parser = Metasploit::Framework::Obfuscation::CRandomizer::Utility.parse(template)
            main_parser.toplevel.statements.each do |s|
              case s.var.type
              when Metasm::C::Function
                # Some function objects such as declarations don't really have
                # any statements, if we run into something like that, skip it.
                next unless s.var.initializer.respond_to?(:statements)
                modifier.modify_function(s)
              end
            end

            main_parser
          end
        end

      end
    end
  end
end