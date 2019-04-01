require 'metasploit/framework/obfuscation/crandomizer/utility'
require 'metasploit/framework/obfuscation/crandomizer/code_factory/base'

module Metasploit
  module Framework
    module Obfuscation
      module CRandomizer
        module CodeFactory

          class GetTickCount < Base
            def initialize
              super
              @dep = ['GetTickCount']
            end

            def stub
              [
                Proc.new { single_gettickcount },
                Proc.new { diff_gettickcount }
              ].sample.call
            end

            private

            def single_gettickcount
              %Q|
              int GetTickCount();
              void stub() {
                GetTickCount();
              }|
            end

            def diff_gettickcount
              var_name_1 = "tickcount_#{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int}"
              var_name_2 = "tickcount_#{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int}"

              %Q|
              int GetTickCount();
              void stub() {
                int #{var_name_1} = GetTickCount();
                int #{var_name_2} = GetTickCount();
                if (#{var_name_2} - #{var_name_1} > 100) {
                  #{var_name_1} = #{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int};
                }
              }|
            end
          end

        end
      end
    end
  end
end