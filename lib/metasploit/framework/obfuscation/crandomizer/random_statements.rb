require 'metasploit/framework/obfuscation/crandomizer/utility'

module Metasploit
  module Framework
    module Obfuscation
      module CRandomizer

        class RandomStatements

          attr_reader :parser
          attr_reader :fake_function_collection
          attr_reader :statements

          # Initializes the RandomStatements class.
          #
          # @param fake_functions [Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory::FakeFunctionCollection]
          # @param s [Metasm::C::Declaration]
          def initialize(p, fake_functions, s=nil)
            @parser = p
            @fake_function_collection = fake_functions
            @statements = [ Proc.new { get_random_statements } ]

            # Only generate fake function calls when the function we are modifying isn't
            # from one of those fake functions (to avoid a recursion).
            if s && fake_function_collection && !fake_function_collection.has_function_name?(s.var.name)
              @statements << Proc.new { get_random_function_call }
            end
          end

          # Returns a random statement.
          #
          # @return [Array<Metasm::C::CExpression>]
          # @return [Array<Metasm::C::Declaration>]
          def get
            statements.sample.call
          end

          private

          # Returns function arguments as a string.
          #
          # @param args [Array<Metasm::C::Variable>]
          # @return [String]
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

          # Returns the arguments (in string) for function declaration.
          #
          # @param args [Array<Metasm::C::Variable]
          # @return [String]
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

          # Returns a random statement from the Code Factory, excluding:
          # * The base class
          # * FakeFunction class
          # * FakeFunctionCollection class
          #
          # @return [Array]
          def get_random_statements
            ignored_classes = [:Base, :FakeFunction, :FakeFunctionCollection]
            class_name = Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory.constants.select { |c|
              next if ignored_classes.include?(c)
              Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory.const_get(c).instance_of?(Class)
            }.sample

            instance = Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory.const_get(class_name).new

            if instance.good_dep?(parser)
              return Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory.const_get(class_name).new.code
            else
              # Call again
              get_random_statements
            end
          end

          # This function is kind of dangerous, because it could cause an
          # infinitely loop by accident when random functions call each other.
          #
          # @return [Array]
          def get_random_function_call
            # There is no fake function collection
            return [] if fake_function_collection.empty?

            fake_function = fake_function_collection.sample
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