module RKelly
  module Visitors
    class DotVisitor < Visitor
      class Node < Struct.new(:node_id, :fields)
        ESCAPE = /([<>"\\])/
        def to_s
          counter = 0
          label = fields.map { |f|
            s = "<f#{counter}> #{f.to_s.gsub(ESCAPE, '\\\\\1').gsub(/[\r\n]/,' ')}"
            counter += 1
            s
          }.join('|')
          "\"#{node_id}\" [\nlabel = \"#{label}\"\nshape = \"record\"\n];"
        end
      end

      class Arrow < Struct.new(:from, :to, :label)
        def to_s
          "\"#{from.node_id}\":f0 -> \"#{to.node_id}\":f0"
        end
      end

      attr_reader :nodes, :arrows
      def initialize
        @stack = []
        @node_index = 0
        @nodes  = []
        @arrows = []
      end

      ## Terminal nodes
      %w{
        BreakNode ContinueNode EmptyStatementNode FalseNode
        NullNode NumberNode ParameterNode RegexpNode ResolveNode StringNode
        ThisNode TrueNode
      }.each do |type|
        define_method(:"visit_#{type}") do |o|
          node = Node.new(@node_index += 1, [type, o.value].compact)
          add_arrow_for(node)
          @nodes << node
        end
      end
      ## End Terminal nodes

      # Single value nodes
      %w{
        AssignExprNode BitwiseNotNode BlockNode DeleteNode ElementNode
        ExpressionStatementNode FunctionBodyNode LogicalNotNode ReturnNode
        ThrowNode TypeOfNode UnaryMinusNode UnaryPlusNode VoidNode
      }.each do |type|
        define_method(:"visit_#{type}") do |o|
          node = Node.new(@node_index += 1, [type])
          add_arrow_for(node)
          @nodes << node
          @stack.push(node)
          o.value && o.value.accept(self)
          @stack.pop
        end
      end
      # End Single value nodes

      # Binary nodes
      %w{
        AddNode BitAndNode BitOrNode BitXOrNode CaseClauseNode CommaNode
        DivideNode DoWhileNode EqualNode GreaterNode GreaterOrEqualNode InNode
        InstanceOfNode LeftShiftNode LessNode LessOrEqualNode LogicalAndNode
        LogicalOrNode ModulusNode MultiplyNode NotEqualNode NotStrictEqualNode
        OpAndEqualNode OpDivideEqualNode OpEqualNode OpLShiftEqualNode
        OpMinusEqualNode OpModEqualNode OpMultiplyEqualNode OpOrEqualNode
        OpPlusEqualNode OpRShiftEqualNode OpURShiftEqualNode OpXOrEqualNode
        RightShiftNode StrictEqualNode SubtractNode SwitchNode
        UnsignedRightShiftNode WhileNode WithNode
      }.each do |type|
        define_method(:"visit_#{type}") do |o|
          node = Node.new(@node_index += 1, [type])
          add_arrow_for(node)
          @nodes << node
          @stack.push(node)
          o.left && o.left.accept(self)
          o.value && o.value.accept(self)
          @stack.pop
        end
      end
      # End Binary nodes

      # Array Value Nodes
      %w{
        ArgumentsNode ArrayNode CaseBlockNode ConstStatementNode
        ObjectLiteralNode SourceElementsNode VarStatementNode
      }.each do |type|
        define_method(:"visit_#{type}") do |o|
          node = Node.new(@node_index += 1, [type])
          add_arrow_for(node)
          @nodes << node
          @stack.push(node)
          o.value && o.value.each { |v| v && v.accept(self) }
          @stack.pop
        end
      end
      # END Array Value Nodes

      # Name and Value Nodes
      %w{
        LabelNode PropertyNode GetterPropertyNode SetterPropertyNode VarDeclNode
      }.each do |type|
        define_method(:"visit_#{type}") do |o|
          node = Node.new(@node_index += 1, [type, o.name || 'NULL'])
          add_arrow_for(node)
          @nodes << node
          @stack.push(node)
          o.value && o.value.accept(self)
          @stack.pop
        end
      end
      # END Name and Value Nodes

      %w{ PostfixNode PrefixNode }.each do |type|
        define_method(:"visit_#{type}") do |o|
          node = Node.new(@node_index += 1, [type, o.value])
          add_arrow_for(node)
          @nodes << node
          @stack.push(node)
          o.operand && o.operand.accept(self)
          @stack.pop
        end
      end

      def visit_ForNode(o)
        node = Node.new(@node_index += 1, ['ForNode'])
        add_arrow_for(node)
        @nodes << node
        @stack.push(node)
        [:init, :test, :counter, :value].each do |method|
          o.send(method) && o.send(method).accept(self)
        end
        @stack.pop
      end

      %w{ IfNode ConditionalNode }.each do |type|
        define_method(:"visit_#{type}") do |o|
          node = Node.new(@node_index += 1, [type])
          add_arrow_for(node)
          @nodes << node
          @stack.push(node)
          [:conditions, :value, :else].each do |method|
            o.send(method) && o.send(method).accept(self)
          end
          @stack.pop
        end
      end

      def visit_ForInNode(o)
        node = Node.new(@node_index += 1, ['ForInNode'])
        add_arrow_for(node)
        @nodes << node
        @stack.push(node)
        [:left, :right, :value].each do |method|
          o.send(method) && o.send(method).accept(self)
        end
        @stack.pop
      end

      def visit_TryNode(o)
        node = Node.new(@node_index += 1, ['TryNode', o.catch_var || 'NULL'])
        add_arrow_for(node)
        @nodes << node
        @stack.push(node)
        [:value, :catch_block, :finally_block].each do |method|
          o.send(method) && o.send(method).accept(self)
        end
        @stack.pop
      end

      def visit_BracketAccessorNode(o)
        node = Node.new(@node_index += 1, ['BracketAccessorNode'])
        add_arrow_for(node)
        @nodes << node
        @stack.push(node)
        [:value, :accessor].each do |method|
          o.send(method) && o.send(method).accept(self)
        end
        @stack.pop
      end

      %w{ NewExprNode FunctionCallNode }.each do |type|
        define_method(:"visit_#{type}") do |o|
          node = Node.new(@node_index += 1, [type])
          add_arrow_for(node)
          @nodes << node
          @stack.push(node)
          [:value, :arguments].each do |method|
            o.send(method) && o.send(method).accept(self)
          end
          @stack.pop
        end
      end

      %w{ FunctionExprNode FunctionDeclNode }.each do |type|
        define_method(:"visit_#{type}") do |o|
          node = Node.new(@node_index += 1, [type, o.value || 'NULL'])
          add_arrow_for(node)
          @nodes << node
          @stack.push(node)
          o.arguments.each { |a| a && a.accept(self) }
          o.function_body && o.function_body.accept(self)
          @stack.pop
        end
      end

      def visit_DotAccessorNode(o)
        node = Node.new(@node_index += 1, ['DotAccessorNode', o.accessor])
        add_arrow_for(node)
        @nodes << node
        @stack.push(node)
        [:value].each do |method|
          o.send(method) && o.send(method).accept(self)
        end
        @stack.pop
      end

      private
      def add_arrow_for(node, label = nil)
        @arrows << Arrow.new(@stack.last, node, label) if @stack.length > 0
      end

    end
  end
end
