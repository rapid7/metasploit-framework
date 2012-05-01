module StateMachine
  module YARD
    module Handlers
      # Handles and processes #transition
      class Transition < Base
        handles method_call(:transition)
        
        def process
          if [StateMachine::Machine, StateMachine::Event, StateMachine::State].include?(owner.class)
            options = {}
            
            # Extract requirements
            ast = statement.parameters.first
            ast.children.each do |assoc|
              # Skip conditionals
              next if %w(if unless).include?(assoc[0].jump(:ident).source)
              
              options[extract_requirement(assoc[0])] = extract_requirement(assoc[1])
            end
            
            owner.transition(options)
          end
        end

        private
          # Extracts the statement requirement from the given node
          def extract_requirement(ast)
            case ast.type
            when :symbol_literal, :string_literal, :array
              extract_node_names(ast, false)
            when :binary
              AllMatcher.instance - extract_node_names(ast.children.last)
            when :var_ref, :vcall
              case ast.source
              when 'nil'
                nil
              when 'same'
                LoopbackMatcher.instance
              else
                AllMatcher.instance
              end
            end
          end
      end
    end
  end
end
