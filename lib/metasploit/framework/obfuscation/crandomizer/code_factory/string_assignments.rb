require 'metasploit/framework/obfuscation/crandomizer/utility'
require 'metasploit/framework/obfuscation/crandomizer/code_factory/base'

module Metasploit
  module Framework
    module Obfuscation
      module CRandomizer
        module CodeFactory

          class StringAssignments < Base
            def stub
              var_name = "fake_string_#{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int}"
              %Q|
              void stub() {
                const char* #{var_name} = "#{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_string}";
              }|
            end
          end

        end
      end
    end
  end
end