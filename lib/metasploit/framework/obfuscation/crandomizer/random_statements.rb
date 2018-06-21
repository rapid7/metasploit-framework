require 'metasploit/framework/obfuscation/crandomizer/utility'

module Metasploit
  module Framework
    module Obfuscation
      module CRandomizer

        class RandomStatements

          attr_reader :fake_functions
          attr_reader :function_list

          def initialize(f, s=nil)
            @fake_functions = f
            @function_list = [ Proc.new { get_random_statements } ]
            if s && !f.has_function_name?(s.var.name)
              @function_list << Proc.new { get_random_function_call }
            end
          end

          def get
            function_list.sample.call
          end

          private

          def make_func_arg_str(args)
            arg_array = []

            args.each do |arg|
              case arg.name
              when 'i'
                arg_array << %Q|#{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_int}|
              when 's'
                arg_array << %Q|"#{Metasploit::Framework::Obfuscation::CRandomizer::Utility.rand_string}"|
              else
                raise "Unknown argument type to process"
              end
            end

            %Q|(#{arg_array.join(', ')})|
          end

          def make_func_declare_arg_str(args)
            arg_array = []
            args.each do |a|
              case a.name
              when 'i'
                arg_array << 'int'
              when 's'
                arg_array << 'char*'
              else
                raise "Unknown argument type to process"
              end
            end

            %Q|(#{arg_array.join(', ')})|
          end

          def get_random_statements
            ignored_classes = [:Base, :FakeFunction, :FakeFunctionCollection]
            class_name = Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory.constants.select { |c|
              next if ignored_classes.include?(c)
              Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory.const_get(c).instance_of?(Class)
            }.sample
            Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory.const_get(class_name).new.code
          end

          # This function is kind of dangerous, because it could cause an
          # infinitely loop by accident when random functions call each other.
          def get_random_function_call
            # There is no fake function collection
            return [] if fake_functions.empty?

            fake_function = fake_functions.sample
            fake_function_name = fake_function.var.name
            fake_function_args = fake_function.var.type.args
            fake_function_declare_args_str = make_func_declare_arg_str(fake_function_args)

            arg_str = make_func_arg_str(fake_function_args)
            template = %Q|
            void #{fake_function_name}#{fake_function_declare_args_str};
            void stub() {
              #{fake_function_name}#{arg_str};
            }|

            parser = Metasploit::Framework::Obfuscation::CRandomizer::Utility.parse(template)
            parser.toplevel.statements.last.var.initializer.statements
          end
        end

      end
    end
  end
end