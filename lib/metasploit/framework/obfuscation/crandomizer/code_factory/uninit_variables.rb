require 'metasploit/framework/obfuscation/crandomizer/utility'
require 'metasploit/framework/obfuscation/crandomizer/code_factory/base'

module Metasploit
  module Framework
    module Obfuscation
      module CRandomizer
        module CodeFactory

          class UninitVariables < Base
            def stub
              [
                Proc.new { char },
                Proc.new { int },
                Proc.new { string }
              ].sample.call
            end

            private

            def char
              %Q|
              void stub() {
                char uninitcharvar#{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int};
              }|
            end

            def int
              %Q|
              void stub() {
                int uninitintvar#{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int};
              }|
            end

            def string
              %Q|
              void stub() {
                const char* uninitstringvar#{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int};
              }|
            end
          end

        end
      end
    end
  end
end