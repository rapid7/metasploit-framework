require 'metasploit/framework/obfuscation/crandomizer/utility'

module Metasploit
  module Framework
    module Obfuscation
      module CRandomizer
        module CodeFactory

          class FakeFunction
            attr_reader :attribute
            attr_reader :return_type
            attr_reader :args
            attr_reader :function_name

            def initialize(func_name)
              @attribute = ['', ' __attribute__((export))'].sample
              @return_type = ['int', 'char*', 'void', ].sample
              @args = ['int i', 'char* s', 'void'].sample
              @function_name = func_name
            end

            def generate_body
              case return_type
              when 'int'
                rand_return_val = Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int
                return_statement = %Q|return #{rand_return_val};|
              when 'char*'
                rand_return_str = Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_string
                return_statement = %Q|return "#{rand_return_str}";|
              else
                return_statement = ''
              end

              %Q|
              #{return_type} #{function_name}#{attribute}(#{args}) {
                #{return_statement}
              }|
            end
          end

        end
      end
    end
  end
end