module RKelly
  module Visitors
    class SexpVisitor < Visitor
      def visit_NumberNode(o)
        [:lit, o.value]
      end

      def visit_RegexpNode(o)
        [:lit, o.value]
      end

      def visit_AssignExprNode(o)
        [:assign, super]
      end

      def visit_VarDeclNode(o)
        [ o.constant? ? :const_decl : :var_decl ] + super(o)
      end

      def visit_VarStatementNode(o)
        [:var, super]
      end

      def visit_PostfixNode(o)
        [:postfix, super, o.value]
      end

      def visit_PrefixNode(o)
        [:prefix, super, o.value]
      end

      def visit_DeleteNode(o)
        [:delete, super]
      end

      def visit_VoidNode(o)
        [:void, super]
      end

      def visit_TypeOfNode(o)
        [:typeof, super]
      end

      def visit_UnaryPlusNode(o)
        [:u_plus, super]
      end

      def visit_UnaryMinusNode(o)
        [:u_minus, super]
      end

      def visit_BitwiseNotNode(o)
        [:bitwise_not, super]
      end

      def visit_LogicalNotNode(o)
        [:not, super]
      end

      def visit_ConstStatementNode(o)
        [:const, super]
      end

      def visit_MultiplyNode(o)
        [:multiply, *super]
      end

      def visit_DivideNode(o)
        [:divide, *super]
      end

      def visit_ModulusNode(o)
        [:modulus, *super]
      end

      def visit_AddNode(o)
        [:add, *super]
      end

      def visit_LeftShiftNode(o)
        [:lshift, *super]
      end

      def visit_RightShiftNode(o)
        [:rshift, *super]
      end

      def visit_UnsignedRightShiftNode(o)
        [:urshift, *super]
      end

      def visit_SubtractNode(o)
        [:subtract, *super]
      end

      def visit_LessNode(o)
        [:less, *super]
      end

      def visit_GreaterNode(o)
        [:greater, *super]
      end

      def visit_LessOrEqualNode(o)
        [:less_or_equal, *super]
      end

      def visit_GreaterOrEqualNode(o)
        [:greater_or_equal, *super]
      end

      def visit_InstanceOfNode(o)
        [:instance_of, *super]
      end

      def visit_EqualNode(o)
        [:equal, *super]
      end

      def visit_NotEqualNode(o)
        [:not_equal, *super]
      end

      def visit_StrictEqualNode(o)
        [:strict_equal, *super]
      end

      def visit_NotStrictEqualNode(o)
        [:not_strict_equal, *super]
      end

      def visit_BitAndNode(o)
        [:bit_and, *super]
      end

      def visit_BitOrNode(o)
        [:bit_or, *super]
      end

      def visit_BitXOrNode(o)
        [:bit_xor, *super]
      end

      def visit_LogicalAndNode(o)
        [:and, *super]
      end

      def visit_LogicalOrNode(o)
        [:or, *super]
      end

      def visit_InNode(o)
        [:in, *super]
      end

      def visit_DoWhileNode(o)
        [:do_while, *super]
      end

      def visit_WhileNode(o)
        [:while, *super]
      end

      def visit_WithNode(o)
        [:with, *super]
      end

      def visit_CaseClauseNode(o)
        [:case, *super]
      end

      def visit_CaseBlockNode(o)
        [:case_block, super]
      end

      def visit_SwitchNode(o)
        [:switch, *super]
      end

      def visit_ForNode(o)
        [ :for, *super]
      end

      def visit_BlockNode(o)
        [:block, super]
      end

      def visit_IfNode(o)
        [:if, *super].compact
      end

      def visit_ConditionalNode(o)
        [:conditional, *super]
      end

      def visit_ForInNode(o)
        [ :for_in, *super]
      end

      def visit_TryNode(o)
        [ :try, *super]
      end

      def visit_EmptyStatementNode(o)
        [:empty]
      end

      def visit_FunctionBodyNode(o)
        [:func_body, super]
      end

      def visit_ResolveNode(o)
        [:resolve, o.value]
      end

      def visit_BracketAccessorNode(o)
        [:bracket_access, *super]
      end

      def visit_NewExprNode(o)
        [:new_expr, *super]
      end

      def visit_ParameterNode(o)
        [:param, o.value]
      end

      def visit_BreakNode(o)
        [:break, o.value].compact
      end

      def visit_ContinueNode(o)
        [:continue, o.value].compact
      end

      def visit_LabelNode(o)
        [:label ] + super
      end

      def visit_ThrowNode(o)
        [:throw, super]
      end

      def visit_ObjectLiteralNode(o)
        [:object, super]
      end

      def visit_PropertyNode(o)
        [ :property ] + super
      end

      def visit_GetterPropertyNode(o)
        [ :getter ] + super
      end

      def visit_SetterPropertyNode(o)
        [ :setter ] + super
      end

      def visit_ElementNode(o)
        [:element, super ]
      end

      def visit_ExpressionStatementNode(o)
        [:expression, super ]
      end

      def visit_OpEqualNode(o)
        [:op_equal, *super ]
      end

      def visit_OpPlusEqualNode(o)
        [:op_plus_equal, *super ]
      end

      def visit_OpMinusEqualNode(o)
        [:op_minus_equal, *super ]
      end

      def visit_OpMultiplyEqualNode(o)
        [:op_multiply_equal, *super ]
      end

      def visit_OpDivideEqualNode(o)
        [:op_divide_equal, *super]
      end

      def visit_OpLShiftEqualNode(o)
        [:op_lshift_equal, *super ]
      end

      def visit_OpRShiftEqualNode(o)
        [:op_rshift_equal, *super ]
      end

      def visit_OpURShiftEqualNode(o)
        [:op_urshift_equal, *super ]
      end

      def visit_OpAndEqualNode(o)
        [:op_and_equal, *super ]
      end

      def visit_OpXOrEqualNode(o)
        [:op_xor_equal, *super ]
      end

      def visit_OpOrEqualNode(o)
        [:op_or_equal, *super ]
      end

      def visit_OpModEqualNode(o)
        [:op_mod_equal, *super]
      end

      def visit_CommaNode(o)
        [:comma, *super]
      end

      def visit_FunctionCallNode(o)
        [:function_call, *super]
      end

      def visit_ArrayNode(o)
        [:array, super]
      end

      def visit_ThisNode(o)
        [:this]
      end

      def visit_ReturnNode(o)
        o.value ? [:return, super] : [:return]
      end

      def visit_FunctionExprNode(o)
        [ :func_expr, *super]
      end

      def visit_FunctionDeclNode(o)
        [ :func_decl, *super]
      end

      def visit_ArgumentsNode(o)
        [:args, super]
      end

      def visit_DotAccessorNode(o)
        [:dot_access,
          super,
          o.accessor
        ]
      end

      def visit_NullNode(o)
        [:nil]
      end
      
      def visit_StringNode(o)
        [:str, o.value]
      end

      def visit_FalseNode(o)
        [:false]
      end

      def visit_TrueNode(o)
        [:true]
      end

    end
  end
end
