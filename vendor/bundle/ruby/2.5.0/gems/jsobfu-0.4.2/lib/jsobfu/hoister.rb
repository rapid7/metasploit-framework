#
# Walks a Javascript AST and finds the immediate members of the
# root scope, which is useful for "hoisting" var and function
# declaration to the top of the function.
#
# Although the auto-hoisting is no longer used, this class is used
# to "discover" a function's variables and scope.
#
class JSObfu::Hoister < RKelly::Visitors::Visitor

  # @return [Hash] the scope maintained while walking the ast
  attr_reader :scope

  # @return [Array<String>] the function names in the first level of this closure
  attr_reader :functions

  # @param opts [Hash] the options hash
  # @option opts [Integer] :max_depth the maximum depth to hoist (1)
  # @option opts [Scope] :parent_scope the owner's scope
  def initialize(opts={})
    @parent_scope = opts.fetch(:parent_scope, nil)
    @max_depth  = 1
    @depth      = 0
    @scope      = {}
    @functions  = []
    super()
  end

  def visit_SourceElementsNode(o)
    return if @max_depth and @depth >= @max_depth
    @depth += 1
    o.value.each { |x| x.accept(self) }
    @depth -= 1
  end

  def visit_VarDeclNode(o)
    scope[o.name] = o
  end

  def visit_FunctionDeclNode(o)    
    functions << o.value
    scope[o.value] = o
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
    UnaryMinusNode UnaryPlusNode UnsignedRightShiftNode
    VoidNode WhileNode WithNode
  }.each do |type|
    define_method(:"visit_#{type}") do |o|
    end
  end

  # @return [String] Javascript that declares the discovered variables
  def scope_declaration(opts={})
    keys = scope.keys.dup
    if opts.fetch(:shuffle, true)
      keys = keys.shuffle
    end

    keys.delete_if { |k| functions.include? k }

    if @parent_scope
      keys.delete_if { |k| @parent_scope.has_key? k }
      keys.map! { |k| @parent_scope.renames[k.to_s] || k }
    end

    if keys.empty? then '' else "var #{keys.join(",")};" end
  end

end
