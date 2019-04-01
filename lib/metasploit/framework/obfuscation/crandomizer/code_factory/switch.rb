require 'metasploit/framework/obfuscation/crandomizer/utility'
require 'metasploit/framework/obfuscation/crandomizer/code_factory/base'

module Metasploit
  module Framework
    module Obfuscation
      module CRandomizer
        module CodeFactory

          class Switch < Base
            def stub
              [
                Proc.new { switch_1 },
                Proc.new { switch_2 }
              ].sample.call
            end

            private

            def switch_1
              var_name = "rndnum#{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int}"
              %Q|
              void stub() {
                int #{var_name} = #{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int};
                switch (#{var_name}) {
                  case #{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int}:
                    #{var_name} = #{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int};
                    break;
                  default:
                    #{var_name} = #{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int};
                    break;
                }
              }|
            end

            def switch_2
              var_name = "rndnum#{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int}"
              %Q|
              void stub() {
                int #{var_name} = #{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int};
                switch (#{var_name}) {
                  case #{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int}:
                    #{var_name} = #{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int};
                    break;
                }
              }|
            end
          end

        end
      end
    end
  end
end