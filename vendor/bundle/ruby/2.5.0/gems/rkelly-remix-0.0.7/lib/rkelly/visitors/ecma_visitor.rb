module RKelly
  module Visitors
    class ECMAVisitor < Visitor
      def initialize
        @indent = 0
      end

      def visit_ParentheticalNode(o)
        "(#{o.value.accept(self)})"
      end

      def visit_SourceElementsNode(o)
        o.value.map { |x| "#{indent}#{x.accept(self)}" }.join("\n")
      end

      def visit_VarStatementNode(o)
        "var #{o.value.map { |x| x.accept(self) }.join(', ')};"
      end

      def visit_ConstStatementNode(o)
        "const #{o.value.map { |x| x.accept(self) }.join(', ')};"
      end

      def visit_VarDeclNode(o)
        "#{o.name}#{o.value ? o.value.accept(self) : nil}"
      end

      def visit_AssignExprNode(o)
        " = #{o.value.accept(self)}"
      end

      def visit_NumberNode(o)
        o.value.to_s
      end

      def visit_ForNode(o)
        init    = o.init ? o.init.accept(self) : ';'
        init    << ';' unless init.end_with? ';' # make sure it has a ;
        test    = o.test ? o.test.accept(self) : ''
        counter = o.counter ? o.counter.accept(self) : ''
        "for(#{init} #{test}; #{counter}) #{o.value.accept(self)}"
      end

      def visit_LessNode(o)
        "#{o.left.accept(self)} < #{o.value.accept(self)}"
      end

      def visit_ResolveNode(o)
        o.value
      end

      def visit_PostfixNode(o)
        "#{o.operand.accept(self)}#{o.value}"
      end

      def visit_PrefixNode(o)
        "#{o.value}#{o.operand.accept(self)}"
      end

      def visit_BlockNode(o)
        @indent += 1
        "{\n#{o.value.accept(self)}\n#{@indent -=1; indent}}"
      end

      def visit_ExpressionStatementNode(o)
        "#{o.value.accept(self)};"
      end

      def visit_OpEqualNode(o)
        "#{o.left.accept(self)} = #{o.value.accept(self)}"
      end

      def visit_FunctionCallNode(o)
        "#{o.value.accept(self)}(#{o.arguments.accept(self)})"
      end

      def visit_ArgumentsNode(o)
        o.value.map { |x| x.accept(self) }.join(', ')
      end

      def visit_StringNode(o)
        o.value
      end

      def visit_NullNode(o)
        "null"
      end

      def visit_FunctionDeclNode(o)
        "#{indent}function #{o.value}" + function_params_and_body(o)
      end

      def visit_ParameterNode(o)
        o.value
      end

      def visit_FunctionBodyNode(o)
        @indent += 1
        "{\n#{o.value.accept(self)}\n#{@indent -=1; indent}}"
      end

      def visit_BreakNode(o)
        "break" + (o.value ? " #{o.value}" : '') + ';'
      end

      def visit_ContinueNode(o)
        "continue" + (o.value ? " #{o.value}" : '') + ';'
      end

      def visit_TrueNode(o)
        "true"
      end

      def visit_FalseNode(o)
        "false"
      end

      def visit_EmptyStatementNode(o)
        ';'
      end

      def visit_RegexpNode(o)
        o.value
      end

      def visit_DotAccessorNode(o)
        "#{o.value.accept(self)}.#{o.accessor}"
      end

      def visit_ThisNode(o)
        "this"
      end

      def visit_BitwiseNotNode(o)
        "~#{o.value.accept(self)}"
      end

      def visit_DeleteNode(o)
        "delete #{o.value.accept(self)}"
      end

      def visit_ArrayNode(o)
        "[#{o.value.map { |x| x ? x.accept(self) : '' }.join(', ')}]"
      end

      def visit_ElementNode(o)
        o.value.accept(self)
      end

      def visit_LogicalNotNode(o)
        "!#{o.value.accept(self)}"
      end

      def visit_UnaryMinusNode(o)
        "-#{o.value.accept(self)}"
      end

      def visit_UnaryPlusNode(o)
        "+#{o.value.accept(self)}"
      end

      def visit_ReturnNode(o)
        "return" + (o.value ? " #{o.value.accept(self)}" : '') + ';'
      end

      def visit_ThrowNode(o)
        "throw #{o.value.accept(self)};"
      end

      def visit_TypeOfNode(o)
        "typeof #{o.value.accept(self)}"
      end

      def visit_VoidNode(o)
        "void(#{o.value.accept(self)})"
      end

      [
        [:Add, '+'],
        [:BitAnd, '&'],
        [:BitOr, '|'],
        [:BitXOr, '^'],
        [:Divide, '/'],
        [:Equal, '=='],
        [:Greater, '>'],
        [:GreaterOrEqual, '>='],
        [:In, 'in'],
        [:InstanceOf, 'instanceof'],
        [:LeftShift, '<<'],
        [:LessOrEqual, '<='],
        [:LogicalAnd, '&&'],
        [:LogicalOr, '||'],
        [:Modulus, '%'],
        [:Multiply, '*'],
        [:NotEqual, '!='],
        [:NotStrictEqual, '!=='],
        [:OpAndEqual, '&='],
        [:OpDivideEqual, '/='],
        [:OpLShiftEqual, '<<='],
        [:OpMinusEqual, '-='],
        [:OpModEqual, '%='],
        [:OpMultiplyEqual, '*='],
        [:OpOrEqual, '|='],
        [:OpPlusEqual, '+='],
        [:OpRShiftEqual, '>>='],
        [:OpURShiftEqual, '>>>='],
        [:OpXOrEqual, '^='],
        [:RightShift, '>>'],
        [:StrictEqual, '==='],
        [:Subtract, '-'],
        [:UnsignedRightShift, '>>>'],
      ].each do |name,op|
        define_method(:"visit_#{name}Node") do |o|
          "#{o.left.accept(self)} #{op} #{o.value.accept(self)}"
        end
      end

      def visit_WhileNode(o)
        "while(#{o.left.accept(self)}) #{o.value.accept(self)}"
      end

      def visit_SwitchNode(o)
        "switch(#{o.left.accept(self)}) #{o.value.accept(self)}"
      end

      def visit_CaseBlockNode(o)
        @indent += 1
        "{\n" + (o.value ? o.value.map { |x| x.accept(self) }.join('') : '') +
          "#{@indent -=1; indent}}"
      end

      def visit_CaseClauseNode(o)
        if o.left
          case_code = "#{indent}case #{o.left.accept(self)}:\n"
        else
          case_code = "#{indent}default:\n"
        end
        @indent += 1
        case_code += "#{o.value.accept(self)}\n"
        @indent -= 1
        case_code
      end

      def visit_DoWhileNode(o)
        "do #{o.left.accept(self)} while(#{o.value.accept(self)});"
      end

      def visit_WithNode(o)
        "with(#{o.left.accept(self)}) #{o.value.accept(self)}"
      end

      def visit_LabelNode(o)
        "#{o.name}: #{o.value.accept(self)}"
      end

      def visit_ObjectLiteralNode(o)
        @indent += 1
        lit = "{" + (o.value.length > 0 ? "\n" : ' ') +
          o.value.map { |x| "#{indent}#{x.accept(self)}" }.join(",\n") +
          (o.value.length > 0 ? "\n" : '') + '}'
        @indent -= 1
        lit
      end

      def visit_PropertyNode(o)
        "#{o.name}: #{o.value.accept(self)}"
      end

      def visit_GetterPropertyNode(o)
        "get #{o.name}" + function_params_and_body(o.value)
      end

      def visit_SetterPropertyNode(o)
        "set #{o.name}" + function_params_and_body(o.value)
      end

      def visit_FunctionExprNode(o)
        name = (o.value == 'function') ? '' : ' '+o.value
        "function" + name + function_params_and_body(o)
      end

      # Helper for all the various function nodes
      def function_params_and_body(o)
        "(#{o.arguments.map { |x| x.accept(self) }.join(', ')}) " +
          "#{o.function_body.accept(self)}"
      end

      def visit_CommaNode(o)
        "#{o.left.accept(self)}, #{o.value.accept(self)}"
      end

      def visit_IfNode(o)
        "if(#{o.conditions.accept(self)}) #{o.value.accept(self)}" +
          (o.else ? " else #{o.else.accept(self)}" : '')
      end

      def visit_ConditionalNode(o)
        "#{o.conditions.accept(self)} ? #{o.value.accept(self)} : " +
          "#{o.else.accept(self)}"
      end

      def visit_ForInNode(o)
        var = o.left.is_a?(RKelly::Nodes::VarDeclNode) ? 'var ' : ''
        "for(#{var}#{o.left.accept(self)} in #{o.right.accept(self)}) " +
          "#{o.value.accept(self)}"
      end

      def visit_TryNode(o)
        "try #{o.value.accept(self)}" +
          (o.catch_block ? " catch(#{o.catch_var}) #{o.catch_block.accept(self)}" : '') +
          (o.finally_block ? " finally #{o.finally_block.accept(self)}" : '')
      end

      def visit_BracketAccessorNode(o)
        "#{o.value.accept(self)}[#{o.accessor.accept(self)}]"
      end

      def visit_NewExprNode(o)
        "new #{o.value.accept(self)}(#{o.arguments.accept(self)})"
      end

      private
      def indent; ' ' * @indent * 2; end
    end
  end
end
