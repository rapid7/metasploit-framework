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
              var_name_1 = "x#{Metasploit::Framework::CRandomizer::Utility.rand_int}"
              var_name_2 = "y#{Metasploit::Framework::CRandomizer::Utility.rand_int}"
              var_name_3 = "delta#{Metasploit::Framework::CRandomizer::Utility.rand_int}"

              %Q|
              int GetTickCount();

              void stub() {
                int #{var_name_1} = GetTickCount();
                int #{var_name_2} = GetTickCount();
                int #{var_name_3} = #{var_name_2} - #{var_name_1};
                switch(#{var_name_3}) {
                  case #{Metasploit::Framework::CRandomizer::Utility.rand_int}:
                    #{var_name_2} = #{Metasploit::Framework::CRandomizer::Utility.rand_int};
                    break;
                  default:
                    #{var_name_1} = #{Metasploit::Framework::CRandomizer::Utility.rand_int};
                }
              }|
            end

            def switch_2
              var_name = "rndnum#{Metasploit::Framework::CRandomizer::Utility.rand_int}"
              %Q|
              void stub() {
                int #{var_name} = #{Metasploit::Framework::CRandomizer::Utility.rand_int};
                switch (#{var_name}) {
                  case #{Metasploit::Framework::CRandomizer::Utility.rand_int}:
                    #{var_name} = #{Metasploit::Framework::CRandomizer::Utility.rand_int};
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