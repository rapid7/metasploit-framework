require 'metasploit/framework/obfuscation/crandomizer/utility'
require 'metasploit/framework/obfuscation/crandomizer/code_factory/base'

module Metasploit
  module Framework
    module Obfuscation
      module CRandomizer
        module CodeFactory

          class Malloc < Base
            def initialize
              super
              @dep = ['malloc']
            end

            def stub
              var_name = "m#{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int}"
              %Q|
              void* malloc(unsigned int);
              void stub() {
                void* #{var_name} = malloc(#{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int});
              }|
            end
          end

        end
      end
    end
  end
end