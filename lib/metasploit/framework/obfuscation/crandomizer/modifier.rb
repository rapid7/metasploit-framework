require 'metasploit/framework/obfuscation/crandomizer/random_statements'

module Metasploit
  module Framework
    module Obfuscation
      module CRandomizer

        class Modifier
          attr_reader :parser
          attr_reader :fake_functions
          attr_reader :weight

          # Initializes a Metasploit::Framework::Obfuscation::CRandomizer::Modifier instance.
          #
          # @param p [Metasploit::C::Parser]
          # @param f [Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory::FakeFunctionCollection]
          # @param w [Integer] Weight of the randomness.
          def initialize(p, f, w)
            @parser = p
            @fake_functions = f
            @weight = w
          end

          # Modifies different if-else blocks recursively.
          #
          # @param s [Metasm::C::Declaration]
          # @return [Metasm::C::Declaration]
          def modify_if_else_blocks(s)
            modify_if(s)
            modify_else_if(s)
            modify_else(s)
            s
          end

          # Modifies an if block.
          #
          # @param s [Metasm::C::Declaration]
          # return [void]
          def modify_if(s)
            new_if_statements = []

            s.bthen.statements.each do |stmt|
              modify_nested_blocks(stmt)
              new_if_statements.concat(get_fake_statement)
              new_if_statements << stmt
            end

            s.bthen.statements = new_if_statements
          end

          # Modifies an else-if block.
          #
          # @param s [Metasm::C::Declaration]
          # @param [void]
          def modify_else_if(s)
            # There could be multiple else if blocks,
            # this gives the current else if block
            elseif_block = s.belse

            while (elseif_block && elseif_block.respond_to?(:bthen)) do
              new_else_if_statements = []

              elseif_block.bthen.statements.each do |stmt|
                modify_nested_blocks(stmt)
                new_else_if_statements.concat(get_fake_statement)
                new_else_if_statements << stmt
              end

              elseif_block.bthen.statements = new_else_if_statements

              # Move on to the next else if block
              elseif_block = elseif_block.belse
            end
          end

          # Modifies an else block.
          #
          # @param s [Metasm::C::Declaration]
          def modify_else(s)
            else_block = s.belse

            # The else block is retrieved this way when there is an else if block
            else_block = s.belse.belse if s.belse.respond_to?(:belse)

            # There is really no else block, let's bail.
            # return unless else_block
            return unless else_block.respond_to?(:statements)

            new_else_statements = []

            else_block.statements.each do |stmt|
              modify_nested_blocks(stmt)
              new_else_statements.concat(get_fake_statement)
              new_else_statements << stmt
            end

            else_block.statements = new_else_statements
          end

          # Modifies a for block.
          #
          # @param s [Metasm::C::Declaration]
          def modify_for(s)
            new_for_statements = []

            s.body.statements.each do |stmt|
              modify_nested_blocks(stmt)
              new_for_statements.concat(get_fake_statement)
              new_for_statements << stmt
            end

            s.body.statements = new_for_statements

            s
          end

          # Modifies a nested block.
          #
          # @param s [Metasm::C::Declaration]
          def modify_nested_blocks(s)
            case s
            when Metasm::C::If
              modify_if_else_blocks(s)
            when Metasm::C::For
              modify_for(s)
            end
          end

          # Modifies a function.
          #
          # @param s [Metasploit::C::Declaration]
          def modify_function(s)
            function_statements = s.var.initializer.statements
            new_function_statements = []

            function_statements.each do |func_stmt|
              unless feeling_lucky?
                new_function_statements << func_stmt
                next
              end

              case func_stmt
              when Metasm::C::If
                new_function_statements << modify_if_else_blocks(func_stmt)
              when Metasm::C::For
                new_function_statements << modify_for(func_stmt)
              else
                new_function_statements.concat(get_fake_statement(s))
                new_function_statements << func_stmt
              end
            end

            unless new_function_statements.empty?
              s.var.initializer.statements = new_function_statements
            end
          end

          private

          # Returns fake statements.
          #
          # @param s [Metasploit::C::Declaration]
          # @return [Array<Metasm::C::CExpression>]
          def get_fake_statement(s=nil)
            random_statements = Metasploit::Framework::Obfuscation::CRandomizer::RandomStatements.new(parser, fake_functions, s)
            random_statements.get
          end

          # Returns a boolean indicating whether a random is above (or equal to) a number or not.
          #
          # @return [Boolean]
          def feeling_lucky?
            n = (rand * 100).to_i
            weight >= n
          end

        end

      end
    end
  end
end