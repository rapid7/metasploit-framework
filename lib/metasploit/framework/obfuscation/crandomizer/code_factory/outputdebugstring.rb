require 'metasploit/framework/obfuscation/crandomizer/utility'
require 'metasploit/framework/obfuscation/crandomizer/code_factory/base'

module Metasploit
  module Framework
    module Obfuscation
      module CRandomizer
        module CodeFactory

          class OutputDebugString < Base
            def initialize
              super
              @dep = ['OutputDebugString']
            end

            def stub
              [
                Proc.new { outputdebugstring_1 },
                Proc.new { outputdebugstring_2 }
              ].sample.call
            end

            private

            def outputdebugstring_1
              %Q|
              void OutputDebugString(const char*);
              void stub() {
                OutputDebugString("#{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_string}");
              }|
            end

            def outputdebugstring_2
              var_name = "msg#{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int}"
              %Q|
              void OutputDebugString(const char*);
              void stub() {
                char* #{var_name} = "#{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_string}";
                OutputDebugString(#{var_name});
              }|
            end
          end

        end
      end
    end
  end
end