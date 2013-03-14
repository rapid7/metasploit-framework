module Treetop
  module Compiler
    class TreetopFile < Runtime::SyntaxNode
      def compile
        (elements.map {|elt| elt.compile}).join
      end
    end
  end
end