module StateMachine
  module YARD
    module Handlers
      # Handles and processes nodes
      class Base < ::YARD::Handlers::Ruby::Base
        private
          # Extracts the value from the node as either a string or symbol
          def extract_node_name(ast)
            case ast.type
            when :symbol_literal
              ast.jump(:ident).source.to_sym
            when :string_literal
              ast.jump(:tstring_content).source
            else
              nil
            end
          end
          
          # Extracts the values from the node as either strings or symbols.
          # If the node isn't an array, it'll be converted to an array.
          def extract_node_names(ast, convert_to_array = true)
            if [nil, :array].include?(ast.type)
              ast.children.map {|child| extract_node_name(child)}
            else
              node_name = extract_node_name(ast)
              convert_to_array ? [node_name] : node_name
            end
          end
      end
    end
  end
end
