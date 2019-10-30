require 'metasploit/framework/obfuscation/crandomizer/utility'
require 'metasploit/framework/obfuscation/crandomizer/code_factory/base'

module Metasploit
  module Framework
    module Obfuscation
      module CRandomizer
        module CodeFactory

          class Printf < Base
            def initialize
              super
              @dep = ['printf']
            end

            def stub
              %Q|
              int printf(const char*);
              void stub() {
                printf("#{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_string}");
              }|
            end
          end

        end
      end
    end
  end
end