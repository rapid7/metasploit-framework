require 'metasploit/framework/obfuscation/crandomizer/utility'
require 'metasploit/framework/obfuscation/crandomizer/code_factory/base'

module Metasploit
  module Framework
    module Obfuscation
      module CRandomizer
        module CodeFactory

          class If < Base
            def stub
              [
                Proc.new { if_stub },
                Proc.new { if_if_else_stub },
                Proc.new { if_else_stub }
              ].sample.call
            end

            private

            def if_stub
              var_name = "xforif#{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int}"

              %Q|
              void stub() {
                int #{var_name} = #{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int};
                if (#{var_name}) {
                  #{var_name} = #{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int};
                }
              }|
            end

            def if_if_else_stub
              var_name = "xforif2#{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int}"

              %Q|
              void stub() {
                int #{var_name} = #{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int};
                if (#{var_name}) {
                  #{var_name} = #{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int};
                } else if (#{var_name} == #{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int}) {
                  #{var_name} = #{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int};
                } else {
                  #{var_name} = #{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int};
                }
              }|
            end

            def if_else_stub
              var_name = "xorif3_#{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int}"

              %Q|
              void stub() {
                signed #{var_name} = #{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int};
                if (#{var_name} == #{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int}) {
                  #{var_name} = #{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int};
                } else {
                  #{var_name} = #{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int};
                }
              }|
            end
          end

        end
      end
    end
  end
end