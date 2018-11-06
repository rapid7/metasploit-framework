module RKelly
  module Nodes
    class Node
      include RKelly::Visitable
      include RKelly::Visitors
      include Enumerable

      attr_accessor :value, :comments, :range, :filename
      def initialize(value)
        @value = value
        @comments = []
        @range = CharRange::EMPTY
        @filename = nil
      end

      # For backwards compatibility
      def line
        @range.from.line
      end

      def ==(other)
        other.is_a?(self.class) && @value == other.value
      end
      alias :=~ :==

      def ===(other)
        other.is_a?(self.class) && @value === other.value
      end

      # Matches nodes with the given pattern (usually a class name of
      # the node) and returns an instance of PointcutVisitor on which
      # #matches can be invoked to get the list of AST nodes that
      # matched.
      #
      #     ast.pointcut(RKelly::Nodes::IfNode).matches --> array of nodes
      #
      def pointcut(pattern)
        case pattern
        when String
          ast = RKelly::Parser.new.parse(pattern)
          # Only take the first statement
          finder = ast.value.first.class.to_s =~ /StatementNode$/ ?
            ast.value.first.value : ast.value.first
          visitor = PointcutVisitor.new(finder)
        else
          visitor = PointcutVisitor.new(pattern)
        end

        visitor.accept(self)
        visitor
      end
      alias :/ :pointcut

      # Generates an s-expression data structure like so:
      #
      #     "var x = 10;" --> [:var, [[:var_decl, :x, [:assign, [:lit, 10]]]]]]
      #
      def to_sexp
        SexpVisitor.new.accept(self)
      end

      # Generates formatted and intented JavaScript source code.
      def to_ecma
        ECMAVisitor.new.accept(self)
      end

      # Generates a graph description in DOT language.  This can be
      # fed into the dot program to generate a graph of the AST:
      #
      #     $ dot -Tpng generated-graph.dot -o graph.png
      #
      def to_dots
        visitor = DotVisitor.new
        visitor.accept(self)
        header = <<-END
digraph g {
graph [ rankdir = "TB" ];
node [
  fontsize = "16"
  shape = "ellipse"
];
edge [ ];
        END
        nodes = visitor.nodes.map { |x| x.to_s }.join("\n")
        counter = 0
        arrows = visitor.arrows.map { |x|
          s = "#{x} [\nid = #{counter}\n];"
          counter += 1
          s
        }.join("\n")
        "#{header}\n#{nodes}\n#{arrows}\n}"
      end

      # Loops through all the syntax nodes.
      def each(&block)
        EnumerableVisitor.new(block).accept(self)
      end

      # This CRASHES!
      # It calls method #s which is nowhere to be found.
      def to_real_sexp
        RealSexpVisitor.new.accept(self)
      end
    end

    %w[EmptyStatement Parenthetical ExpressionStatement True Delete Return TypeOf
       SourceElements Number LogicalNot AssignExpr FunctionBody
       ObjectLiteral UnaryMinus Throw This BitwiseNot Element String
       Array CaseBlock Null Break Parameter Block False Void Regexp
       Arguments Attr Continue ConstStatement UnaryPlus VarStatement].each do |node|
      eval "class #{node}Node < Node; end"
    end
  end
end
