# -*- coding: binary -*-
module RKelly
  module Visitors
    class EvaluationVisitor < Visitor
      attr_reader :scope_chain
      def initialize(scope)
        super()
        @scope_chain = scope
        @operand = []
      end

      def visit_SourceElementsNode(o)
        o.value.each { |x|
          next if scope_chain.returned?
          x.accept(self)
        }
      end

      def visit_FunctionDeclNode(o)
      end

      def visit_VarStatementNode(o)
        o.value.each { |x| x.accept(self) }
      end

      def visit_VarDeclNode(o)
        @operand << o.name
        o.value.accept(self) if o.value
        @operand.pop
      end

      def visit_IfNode(o)
        truthiness = o.conditions.accept(self)
        if truthiness.value && truthiness.value != 0
          o.value.accept(self)
        else
          o.else && o.else.accept(self)
        end
      end

      def visit_ResolveNode(o)
        scope_chain[o.value]
      end

      def visit_ThisNode(o)
        scope_chain.this
      end

      def visit_ExpressionStatementNode(o)
        o.value.accept(self)
      end

      def visit_AddNode(o)
        left  = to_primitive(o.left.accept(self), 'Number')
        right = to_primitive(o.value.accept(self), 'Number')

        if left.value.is_a?(::String) || right.value.is_a?(::String)
          RKelly::JS::Property.new(:add,
            "#{left.value}#{right.value}"
          )
        else
          additive_operator(:+, left, right)
        end
      end

      def visit_SubtractNode(o)
        RKelly::JS::Property.new(:subtract,
          o.left.accept(self).value - o.value.accept(self).value
        )
      end

      def visit_MultiplyNode(o)
        left = to_number(o.left.accept(self)).value
        right = to_number(o.value.accept(self)).value
        return_val = 
          if [left, right].any? { |x| x.respond_to?(:nan?) && x.nan? }
            RKelly::JS::NaN.new
          else
            [left, right].any? { |x|
              x.respond_to?(:intinite?) && x.infinite?
            } && [left, right].any? { |x| x == 0
            } ? RKelly::JS::NaN.new : left * right
          end
        RKelly::JS::Property.new(:multiple, return_val)
      end

      def visit_DivideNode(o)
        left = to_number(o.left.accept(self)).value
        right = to_number(o.value.accept(self)).value
        return_val = 
          if [left, right].any? { |x|
            x.respond_to?(:nan?) && x.nan? ||
            x.respond_to?(:intinite?) && x.infinite?
          }
            RKelly::JS::NaN.new
          elsif [left, right].all? { |x| x == 0 }
            RKelly::JS::NaN.new
          elsif right == 0
            left * (right.eql?(0) ? (1.0/0.0) : (-1.0/0.0))
          else
            left / right
          end
        RKelly::JS::Property.new(:divide, return_val)
      end

      def visit_ModulusNode(o)
        left = to_number(o.left.accept(self)).value
        right = to_number(o.value.accept(self)).value
        return_val = 
          if [left, right].any? { |x| x.respond_to?(:nan?) && x.nan? }
            RKelly::JS::NaN.new
          elsif [left, right].all? { |x| x.respond_to?(:infinite?) && x.infinite? }
            RKelly::JS::NaN.new
          elsif right == 0
            RKelly::JS::NaN.new
          elsif left.respond_to?(:infinite?) && left.infinite?
            RKelly::JS::NaN.new
          elsif right.respond_to?(:infinite?) && right.infinite?
            left
          else
            left % right
          end
        RKelly::JS::Property.new(:divide, return_val)
      end

      def visit_OpEqualNode(o)
        left = o.left.accept(self)
        right = o.value.accept(self)
        left.value = right.value
        left.function = right.function
        left
      end

      def visit_OpPlusEqualNode(o)
        o.left.accept(self).value += o.value.accept(self).value
      end

      def visit_AssignExprNode(o)
        scope_chain[@operand.last] = o.value.accept(self)
      end

      def visit_NumberNode(o)
        RKelly::JS::Property.new(o.value, o.value)
      end

      def visit_VoidNode(o)
        o.value.accept(self)
        RKelly::JS::Property.new(:undefined, :undefined)
      end

      def visit_NullNode(o)
        RKelly::JS::Property.new(nil, nil)
      end

      def visit_TrueNode(o)
        RKelly::JS::Property.new(true, true)
      end

      def visit_FalseNode(o)
        RKelly::JS::Property.new(false, false)
      end

      def visit_StringNode(o)
        RKelly::JS::Property.new(:string,
          o.value.gsub(/\A['"]/, '').gsub(/['"]$/, '')
        )
      end

      def visit_FunctionCallNode(o)
        left      = o.value.accept(self)
        arguments = o.arguments.accept(self)
        call_function(left, arguments)
      end

      def visit_NewExprNode(o)
        visit_FunctionCallNode(o)
      end

      def visit_DotAccessorNode(o)
        left = o.value.accept(self)
        right = left.value[o.accessor]
        right.binder = left.value
        right
      end

      def visit_EqualNode(o)
        left = o.left.accept(self)
        right = o.value.accept(self)

        RKelly::JS::Property.new(:equal_node, left.value == right.value)
      end

      def visit_BlockNode(o)
        o.value.accept(self)
      end

      def visit_FunctionBodyNode(o)
        o.value.accept(self)
        scope_chain.return
      end

      def visit_ReturnNode(o)
        scope_chain.return = o.value.accept(self)
      end

      def visit_BitwiseNotNode(o)
        orig = o.value.accept(self)
        number = to_int_32(orig)
        RKelly::JS::Property.new(nil, ~number.value)
      end

      def visit_PostfixNode(o)
        orig = o.operand.accept(self)
        number = to_number(orig)
        case o.value
        when '++'
          orig.value = number.value + 1
        when '--'
          orig.value = number.value - 1
        end
        number
      end

      def visit_PrefixNode(o)
        orig = o.operand.accept(self)
        number = to_number(orig)
        case o.value
        when '++'
          orig.value = number.value + 1
        when '--'
          orig.value = number.value - 1
        end
        orig
      end

      def visit_LogicalNotNode(o)
        bool = to_boolean(o.value.accept(self))
        bool.value = !bool.value
        bool
      end

      def visit_ArgumentsNode(o)
        o.value.map { |x| x.accept(self) }
      end

      def visit_TypeOfNode(o)
        val = o.value.accept(self)
        return RKelly::JS::Property.new(:string, 'object') if val.value.nil?

        case val.value
        when String
          RKelly::JS::Property.new(:string, 'string')
        when Numeric
          RKelly::JS::Property.new(:string, 'number')
        when true
          RKelly::JS::Property.new(:string, 'boolean')
        when false
          RKelly::JS::Property.new(:string, 'boolean')
        when :undefined
          RKelly::JS::Property.new(:string, 'undefined')
        else
          RKelly::JS::Property.new(:object, 'object')
        end
      end

      def visit_UnaryPlusNode(o)
        orig = o.value.accept(self)
        to_number(orig)
      end

      def visit_UnaryMinusNode(o)
        orig = o.value.accept(self)
        v = to_number(orig)
        v.value = v.value == 0 ? -0.0 : 0 - v.value
        v
      end

      %w{
        ArrayNode BitAndNode BitOrNode
        BitXOrNode BracketAccessorNode BreakNode
        CaseBlockNode CaseClauseNode CommaNode ConditionalNode
        ConstStatementNode ContinueNode DeleteNode
        DoWhileNode ElementNode EmptyStatementNode
        ForInNode ForNode
        FunctionExprNode GetterPropertyNode GreaterNode GreaterOrEqualNode
        InNode InstanceOfNode LabelNode LeftShiftNode LessNode
        LessOrEqualNode LogicalAndNode LogicalOrNode
        NotEqualNode NotStrictEqualNode
        ObjectLiteralNode OpAndEqualNode OpDivideEqualNode
        OpLShiftEqualNode OpMinusEqualNode OpModEqualNode
        OpMultiplyEqualNode OpOrEqualNode OpRShiftEqualNode
        OpURShiftEqualNode OpXOrEqualNode ParameterNode
        PropertyNode RegexpNode RightShiftNode
        SetterPropertyNode StrictEqualNode
        SwitchNode ThrowNode TryNode
        UnsignedRightShiftNode
        WhileNode WithNode
      }.each do |type|
        define_method(:"visit_#{type}") do |o|
          raise "#{type} not defined"
        end
      end

      private
      def to_number(object)
        return RKelly::JS::Property.new('0', 0) unless object.value

        return_val =
          case object.value
          when :undefined
            RKelly::JS::NaN.new
          when false
            0
          when true
            1
          when Numeric
            object.value
          when ::String
            s = object.value.gsub(/(\A[\s\xB\xA0]*|[\s\xB\xA0]*\Z)/n, '')
            if s.length == 0
              0
            else
              case s
              when /^([+-])?Infinity/
                $1 == '-' ? -1.0/0.0 : 1.0/0.0
              when /\A[-+]?\d+\.\d*(?:[eE][-+]?\d+)?$|\A[-+]?\d+(?:\.\d*)?[eE][-+]?\d+$|\A[-+]?\.\d+(?:[eE][-+]?\d+)?$/, /\A[-+]?0[xX][\da-fA-F]+$|\A[+-]?0[0-7]*$|\A[+-]?\d+$/
                s.gsub!(/\.(\D)/, '.0\1') if s =~ /\.\w/
                s.gsub!(/\.$/, '.0') if s =~ /\.$/
                s.gsub!(/^\./, '0.') if s =~ /^\./
                s.gsub!(/^([+-])\./, '\10.') if s =~ /^[+-]\./
                s = s.gsub(/^[0]*/, '') if /^0[1-9]+$/.match(s)
                eval(s)
              else
                RKelly::JS::NaN.new
              end
            end
          when RKelly::JS::Base
            return to_number(to_primitive(object, 'Number'))
          end
        RKelly::JS::Property.new(nil, return_val)
      end

      def to_boolean(object)
        return RKelly::JS::Property.new(false, false) unless object.value
        value = object.value
        boolean =
          case value
          when :undefined
            false
          when true
            true
          when Numeric
            value == 0 || value.respond_to?(:nan?) && value.nan? ? false : true
          when ::String
            value.length == 0 ? false : true
          when RKelly::JS::Base
            true
          else
            raise
          end
        RKelly::JS::Property.new(boolean, boolean)
      end

      def to_int_32(object)
        number = to_number(object)
        value = number.value
        return number if value == 0
        if value.respond_to?(:nan?) && (value.nan? || value.infinite?)
          RKelly::JS::Property.new(nil, 0)
        end
        value = ((value < 0 ? -1 : 1) * value.abs.floor) % (2 ** 32)
        if value >= 2 ** 31
          RKelly::JS::Property.new(nil, value - (2 ** 32))
        else
          RKelly::JS::Property.new(nil, value)
        end
      end

      def to_primitive(object, preferred_type = nil)
        return object unless object.value
        case object.value
        when false, true, :undefined, ::String, Numeric
          RKelly::JS::Property.new(nil, object.value)
        when RKelly::JS::Base
          call_function(object.value.default_value(preferred_type))
        end
      end

      def additive_operator(operator, left, right)
        left, right = to_number(left).value, to_number(right).value

        left = left.respond_to?(:nan?) && left.nan? ? 0.0/0.0 : left
        right = right.respond_to?(:nan?) && right.nan? ? 0.0/0.0 : right

        result = left.send(operator, right)
        result = result.respond_to?(:nan?) && result.nan? ? JS::NaN.new : result

        RKelly::JS::Property.new(operator, result)
      end

      def call_function(property, arguments = [])
        function  = property.function || property.value
        case function
        when RKelly::JS::Function
          scope_chain.new_scope { |chain|
            function.js_call(chain, *arguments)
          }
        when UnboundMethod
          RKelly::JS::Property.new(:ruby,
            function.bind(property.binder).call(*(arguments.map { |x| x.value}))
          )
        else
          RKelly::JS::Property.new(:ruby,
            function.call(*(arguments.map { |x| x.value }))
          )
        end
      end
    end
  end
end
