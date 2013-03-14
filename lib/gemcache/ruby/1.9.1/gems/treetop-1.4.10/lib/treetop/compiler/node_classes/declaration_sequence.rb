module Treetop
  module Compiler
    class DeclarationSequence < Runtime::SyntaxNode

      def compile(builder)
        unless rules.empty?
          builder.method_declaration("root") do
            builder << "@root ||= :#{rules.first.name}"
          end
          builder.newline
        end
        
        declarations.each do |declaration|
          declaration.compile(builder)
          builder.newline
        end
      end
      
      def rules
        declarations.select { |declaration| declaration.instance_of?(ParsingRule) }
      end
    end
  end
end