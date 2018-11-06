module RKelly
  module Visitors
    class FunctionVisitor < Visitor
      attr_reader :scope_chain
      def initialize(scope)
        super()
        @scope_chain = scope
      end

      def visit_SourceElementsNode(o)
        o.value.each { |x| x.accept(self) }
      end

      def visit_FunctionDeclNode(o)
        if o.value
          scope_chain[o.value].value = RKelly::JS::Function.new(o.function_body, o.arguments)
        end
      end

      %w{
        AddNode ArgumentsNode ArrayNode AssignExprNode BitAndNode BitOrNode
        BitXOrNode BitwiseNotNode BlockNode BracketAccessorNode BreakNode
        CaseBlockNode CaseClauseNode CommaNode ConditionalNode
        ConstStatementNode ContinueNode DeleteNode DivideNode
        DoWhileNode DotAccessorNode ElementNode EmptyStatementNode EqualNode
        ExpressionStatementNode FalseNode ForInNode ForNode FunctionBodyNode
        FunctionExprNode GetterPropertyNode GreaterNode GreaterOrEqualNode
        IfNode InNode InstanceOfNode LabelNode LeftShiftNode LessNode
        LessOrEqualNode LogicalAndNode LogicalNotNode LogicalOrNode ModulusNode
        MultiplyNode NewExprNode NotEqualNode NotStrictEqualNode NullNode
        NumberNode ObjectLiteralNode OpAndEqualNode OpDivideEqualNode
        OpEqualNode OpLShiftEqualNode OpMinusEqualNode OpModEqualNode
        OpMultiplyEqualNode OpOrEqualNode OpPlusEqualNode OpRShiftEqualNode
        OpURShiftEqualNode OpXOrEqualNode ParameterNode PostfixNode PrefixNode
        PropertyNode RegexpNode ResolveNode ReturnNode RightShiftNode
        SetterPropertyNode StrictEqualNode StringNode
        SubtractNode SwitchNode ThisNode ThrowNode TrueNode TryNode TypeOfNode
        UnaryMinusNode UnaryPlusNode UnsignedRightShiftNode VarDeclNode
        VarStatementNode VoidNode WhileNode WithNode
      }.each do |type|
        define_method(:"visit_#{type}") do |o|
        end
      end
    end
  end
end
