require 'metasploit/framework/obfuscation/crandomizer/utility'
require 'metasploit/framework/obfuscation/crandomizer/code_factory/base'

module Metasploit
  module Framework
    module Obfuscation
      module CRandomizer
        module CodeFactory

          class IntAssignments < Base
            def stub
              var_name = "fakeint_#{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int}"
              %Q|
              void stub() {
                int #{var_name} = #{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int};
              }|
            end
          end

        end
      end
    end
  end
end