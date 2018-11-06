/* vim: set filetype=racc : */

class RKelly::GeneratedParser

/* Literals */
token NULL TRUE FALSE

/* keywords */
token BREAK CASE CATCH CONST CONTINUE DEBUGGER DEFAULT DELETE DO ELSE
token FINALLY FOR FUNCTION IF IN INSTANCEOF NEW RETURN SWITCH THIS THROW TRY
token TYPEOF VAR VOID WHILE WITH

/* reserved keywords */
token RESERVED

/* punctuators */
token EQEQ NE                     /* == and != */
token STREQ STRNEQ                /* === and !== */
token LE GE                       /* < and > */
token OR AND                      /* || and && */
token PLUSPLUS MINUSMINUS         /* ++ and --  */
token LSHIFT                      /* << */
token RSHIFT URSHIFT              /* >> and >>> */
token PLUSEQUAL MINUSEQUAL        /* += and -= */
token MULTEQUAL DIVEQUAL          /* *= and /= */
token LSHIFTEQUAL                 /* <<= */
token RSHIFTEQUAL URSHIFTEQUAL    /* >>= and >>>= */
token ANDEQUAL MODEQUAL           /* &= and %= */
token XOREQUAL OREQUAL            /* ^= and |= */

/* Terminal types */
token REGEXP
token NUMBER
token STRING
token IDENT

token AUTOPLUSPLUS AUTOMINUSMINUS IF_WITHOUT_ELSE

prechigh
  nonassoc ELSE
  nonassoc IF_WITHOUT_ELSE
preclow

rule
  SourceElements:
    /* nothing */ 			{ result = SourceElementsNode.new([]) }
  | SourceElementList			{ result = SourceElementsNode.new([val].flatten) }

  SourceElementList:
    SourceElement
  | SourceElementList SourceElement        { result = val.flatten }
  ;

  SourceElement:
    FunctionDeclaration
  | Statement
  ;

  Statement:
    Block
  | VariableStatement
  | ConstStatement
  | EmptyStatement
  | ExprStatement
  | IfStatement
  | IterationStatement
  | ContinueStatement
  | BreakStatement
  | ReturnStatement
  | WithStatement
  | SwitchStatement
  | LabelledStatement
  | ThrowStatement
  | TryStatement
  | DebuggerStatement
  ;

  Literal:
    NULL    { result = NullNode.new(val.first) }
  | TRUE    { result = TrueNode.new(val.first) }
  | FALSE   { result = FalseNode.new(val.first) }
  | NUMBER  { result = NumberNode.new(val.first) }
  | STRING  { result = StringNode.new(val.first) }
  | REGEXP  { result = RegexpNode.new(val.first) }
  ;

  Property:
    IdentName ':' AssignmentExpr {
      result = PropertyNode.new(val[0], val[2])
    }
  | STRING ':' AssignmentExpr { result = PropertyNode.new(val.first, val.last) }
  | NUMBER ':' AssignmentExpr { result = PropertyNode.new(val.first, val.last) }
  | IDENT IdentName '(' ')' FunctionBody  {
      klass = property_class_for(val.first)
      yyabort unless klass
      result = klass.new(val[1], FunctionExprNode.new(nil, val[4]))
    }
  | IDENT IdentName '(' FormalParameterList ')' FunctionBody {
      klass = property_class_for(val.first)
      yyabort unless klass
      result = klass.new(val[1], FunctionExprNode.new(nil, val[5], val[3]))
    }
  ;

  IdentName:
    IDENT
  | NULL | TRUE | FALSE
  | BREAK | CASE | CATCH | CONST | CONTINUE | DEBUGGER | DEFAULT | DELETE | DO | ELSE
  | FINALLY | FOR | FUNCTION | IF | IN | INSTANCEOF | NEW | RETURN | SWITCH | THIS | THROW | TRY
  | TYPEOF | VAR | VOID | WHILE | WITH
  | RESERVED
  ;

  PropertyList:
    Property                    { result = val }
  | PropertyList ',' Property   { result = [val.first, val.last].flatten }
  ;

  PrimaryExpr:
    PrimaryExprNoBrace
  | '{' '}'                   { result = ObjectLiteralNode.new([]) }
  | '{' PropertyList '}'      { result = ObjectLiteralNode.new(val[1]) }
  | '{' PropertyList ',' '}'  { result = ObjectLiteralNode.new(val[1]) }
  ;

  PrimaryExprNoBrace:
    THIS          { result = ThisNode.new(val.first) }
  | Literal
  | ArrayLiteral
  | IDENT         { result = ResolveNode.new(val.first) }
  | '(' Expr ')'  { result = ParentheticalNode.new(val[1]) }
  ;

  ArrayLiteral:
    '[' ElisionOpt ']'           { result = ArrayNode.new([] + [nil] * val[1]) }
  | '[' ElementList ']'                 { result = ArrayNode.new(val[1]) }
  | '[' ElementList ',' ElisionOpt ']'  {
      result = ArrayNode.new(val[1] + [nil] * val[3])
    }
  ;

  ElementList:
    ElisionOpt AssignmentExpr {
      result = [nil] * val[0] + [ElementNode.new(val[1])]
    }
  | ElementList ',' ElisionOpt AssignmentExpr {
      result = [val[0], [nil] * val[2], ElementNode.new(val[3])].flatten
    }
  ;

  ElisionOpt:
    /* nothing */ { result = 0 }
  | Elision
  ;

  Elision:
    ',' { result = 1 }
  | Elision ',' { result = val.first + 1 }
  ;

  MemberExpr:
    PrimaryExpr
  | FunctionExpr
  | MemberExpr '[' Expr ']' { result = BracketAccessorNode.new(val[0], val[2]) }
  | MemberExpr '.' IdentName { result = DotAccessorNode.new(val[0], val[2]) }
  | NEW MemberExpr Arguments { result = NewExprNode.new(val[1], val[2]) }
  ;

  MemberExprNoBF:
    PrimaryExprNoBrace
  | MemberExprNoBF '[' Expr ']' {
      result = BracketAccessorNode.new(val[0], val[2])
    }
  | MemberExprNoBF '.' IdentName { result = DotAccessorNode.new(val[0], val[2]) }
  | NEW MemberExpr Arguments    { result = NewExprNode.new(val[1], val[2]) }
  ;

  NewExpr:
    MemberExpr
  | NEW NewExpr { result = NewExprNode.new(val[1], ArgumentsNode.new([])) }
  ;

  NewExprNoBF:
    MemberExprNoBF
  | NEW NewExpr { result = NewExprNode.new(val[1], ArgumentsNode.new([])) }
  ;

  CallExpr:
    MemberExpr Arguments  { result = FunctionCallNode.new(val[0], val[1]) }
  | CallExpr Arguments    { result = FunctionCallNode.new(val[0], val[1]) }
  | CallExpr '[' Expr ']' { result = BracketAccessorNode.new(val[0], val[2]) }
  | CallExpr '.' IdentName { result = DotAccessorNode.new(val[0], val[2]) }
  ;

  CallExprNoBF:
    VOID '(' MemberExpr ')' { result = FunctionCallNode.new(ResolveNode.new(val[0]), val[2]) }
  | MemberExprNoBF Arguments  { result = FunctionCallNode.new(val[0], val[1]) }
  | CallExprNoBF Arguments    { result = FunctionCallNode.new(val[0], val[1]) }
  | CallExprNoBF '[' Expr ']' { result = BracketAccessorNode.new(val[0], val[2]) }
  | CallExprNoBF '.' IdentName { result = DotAccessorNode.new(val[0], val[2]) }
  ;

  Arguments:
    '(' ')'               { result = ArgumentsNode.new([]) }
  | '(' ArgumentList ')'  { result = ArgumentsNode.new(val[1]); }
  ;

  ArgumentList:
    AssignmentExpr                      { result = val }
  | ArgumentList ',' AssignmentExpr     { result = [val[0], val[2]].flatten }
  ;

  LeftHandSideExpr:
    NewExpr
  | CallExpr
  ;

  LeftHandSideExprNoBF:
    NewExprNoBF
  | CallExprNoBF
  ;

  PostfixExpr:
    LeftHandSideExpr
  | LeftHandSideExpr PLUSPLUS   { result = PostfixNode.new(val[0], '++') }
  | LeftHandSideExpr MINUSMINUS { result = PostfixNode.new(val[0], '--') }
  ;

  PostfixExprNoBF:
    LeftHandSideExprNoBF
  | LeftHandSideExprNoBF PLUSPLUS   { result = PostfixNode.new(val[0], '++') }
  | LeftHandSideExprNoBF MINUSMINUS { result = PostfixNode.new(val[0], '--') }
  ;

  UnaryExprCommon:
    DELETE UnaryExpr     { result = DeleteNode.new(val[1]) }
  | VOID UnaryExpr       { result = VoidNode.new(val[1]) }
  | TYPEOF UnaryExpr          { result = TypeOfNode.new(val[1]) }
  | PLUSPLUS UnaryExpr        { result = PrefixNode.new(val[1], '++') }
  /* FIXME: Not sure when this can ever happen
  | AUTOPLUSPLUS UnaryExpr    { result = makePrefixNode($2, OpPlusPlus); } */
  | MINUSMINUS UnaryExpr      { result = PrefixNode.new(val[1], '--') }
  /* FIXME: Not sure when this can ever happen
  | AUTOMINUSMINUS UnaryExpr  { result = makePrefixNode($2, OpMinusMinus); } */
  | '+' UnaryExpr             { result = UnaryPlusNode.new(val[1]) }
  | '-' UnaryExpr             { result = UnaryMinusNode.new(val[1]) }
  | '~' UnaryExpr             { result = BitwiseNotNode.new(val[1]) }
  | '!' UnaryExpr             { result = LogicalNotNode.new(val[1]) }
  ;

  UnaryExpr:
    PostfixExpr
  | UnaryExprCommon
  ;

  UnaryExprNoBF:
    PostfixExprNoBF
  | UnaryExprCommon
  ;

  MultiplicativeExpr:
    UnaryExpr
  | MultiplicativeExpr '*' UnaryExpr { result = MultiplyNode.new(val[0],val[2])}
  | MultiplicativeExpr '/' UnaryExpr { result = DivideNode.new(val[0], val[2]) }
  | MultiplicativeExpr '%' UnaryExpr { result = ModulusNode.new(val[0], val[2])}
  ;

  MultiplicativeExprNoBF:
    UnaryExprNoBF
  | MultiplicativeExprNoBF '*' UnaryExpr { result = MultiplyNode.new(val[0], val[2]) }
  | MultiplicativeExprNoBF '/' UnaryExpr { result = DivideNode.new(val[0],val[2]) }
  | MultiplicativeExprNoBF '%' UnaryExpr { result = ModulusNode.new(val[0], val[2]) }
  ;

  AdditiveExpr:
    MultiplicativeExpr
  | AdditiveExpr '+' MultiplicativeExpr { result = AddNode.new(val[0], val[2]) }
  | AdditiveExpr '-' MultiplicativeExpr { result = SubtractNode.new(val[0], val[2]) }
  ;

  AdditiveExprNoBF:
    MultiplicativeExprNoBF
  | AdditiveExprNoBF '+' MultiplicativeExpr { result = AddNode.new(val[0], val[2]) }
  | AdditiveExprNoBF '-' MultiplicativeExpr { result = SubtractNode.new(val[0], val[2]) }
  ;

  ShiftExpr:
    AdditiveExpr
  | ShiftExpr LSHIFT AdditiveExpr   { result = LeftShiftNode.new(val[0], val[2]) }
  | ShiftExpr RSHIFT AdditiveExpr   { result = RightShiftNode.new(val[0], val[2]) }
  | ShiftExpr URSHIFT AdditiveExpr  { result = UnsignedRightShiftNode.new(val[0], val[2]) }
  ;

  ShiftExprNoBF:
    AdditiveExprNoBF
  | ShiftExprNoBF LSHIFT AdditiveExpr   { result = LeftShiftNode.new(val[0], val[2]) }
  | ShiftExprNoBF RSHIFT AdditiveExpr   { result = RightShiftNode.new(val[0], val[2]) }
  | ShiftExprNoBF URSHIFT AdditiveExpr  { result = UnsignedRightShiftNode.new(val[0], val[2]) }
  ;

  RelationalExpr:
    ShiftExpr
  | RelationalExpr '<' ShiftExpr        { result = LessNode.new(val[0], val[2])}
  | RelationalExpr '>' ShiftExpr        { result = GreaterNode.new(val[0], val[2]) }
  | RelationalExpr LE ShiftExpr         { result = LessOrEqualNode.new(val[0], val[2]) }
  | RelationalExpr GE ShiftExpr         { result = GreaterOrEqualNode.new(val[0], val[2]) }
  | RelationalExpr INSTANCEOF ShiftExpr { result = InstanceOfNode.new(val[0], val[2]) }
  | RelationalExpr IN ShiftExpr    { result = InNode.new(val[0], val[2]) }
  ;

  RelationalExprNoIn:
    ShiftExpr
  | RelationalExprNoIn '<' ShiftExpr    { result = LessNode.new(val[0], val[2])}
  | RelationalExprNoIn '>' ShiftExpr    { result = GreaterNode.new(val[0], val[2]) }
  | RelationalExprNoIn LE ShiftExpr     { result = LessOrEqualNode.new(val[0], val[2]) }
  | RelationalExprNoIn GE ShiftExpr     { result = GreaterOrEqualNode.new(val[0], val[2]) }
  | RelationalExprNoIn INSTANCEOF ShiftExpr
                                        { result = InstanceOfNode.new(val[0], val[2]) }
  ;

  RelationalExprNoBF:
    ShiftExprNoBF
  | RelationalExprNoBF '<' ShiftExpr    { result = LessNode.new(val[0], val[2]) }
  | RelationalExprNoBF '>' ShiftExpr    { result = GreaterNode.new(val[0], val[2]) }
  | RelationalExprNoBF LE ShiftExpr     { result = LessOrEqualNode.new(val[0], val[2]) }
  | RelationalExprNoBF GE ShiftExpr     { result = GreaterOrEqualNode.new(val[0], val[2]) }
  | RelationalExprNoBF INSTANCEOF ShiftExpr
                                        { result = InstanceOfNode.new(val[0], val[2]) }
  | RelationalExprNoBF IN ShiftExpr     { result = InNode.new(val[0], val[2]) }
  ;

  EqualityExpr:
    RelationalExpr
  | EqualityExpr EQEQ RelationalExpr    { result = EqualNode.new(val[0], val[2]) }
  | EqualityExpr NE RelationalExpr      { result = NotEqualNode.new(val[0], val[2]) }
  | EqualityExpr STREQ RelationalExpr   { result = StrictEqualNode.new(val[0], val[2]) }
  | EqualityExpr STRNEQ RelationalExpr  { result = NotStrictEqualNode.new(val[0], val[2]) }
  ;

  EqualityExprNoIn:
    RelationalExprNoIn
  | EqualityExprNoIn EQEQ RelationalExprNoIn
                                        { result = EqualNode.new(val[0], val[2]) }
  | EqualityExprNoIn NE RelationalExprNoIn
                                        { result = NotEqualNode.new(val[0], val[2]) }
  | EqualityExprNoIn STREQ RelationalExprNoIn
                                        { result = StrictEqualNode.new(val[0], val[2]) }
  | EqualityExprNoIn STRNEQ RelationalExprNoIn
                                        { result = NotStrictEqualNode.new(val[0], val[2]) }
  ;

  EqualityExprNoBF:
    RelationalExprNoBF
  | EqualityExprNoBF EQEQ RelationalExpr
                                        { result = EqualNode.new(val[0], val[2]) }
  | EqualityExprNoBF NE RelationalExpr  { result = NotEqualNode.new(val[0], val[2]) }
  | EqualityExprNoBF STREQ RelationalExpr
                                        { result = StrictEqualNode.new(val[0], val[2]) }
  | EqualityExprNoBF STRNEQ RelationalExpr
                                        { result = NotStrictEqualNode.new(val[0], val[2]) }
  ;

  BitwiseANDExpr:
    EqualityExpr
  | BitwiseANDExpr '&' EqualityExpr     { result = BitAndNode.new(val[0], val[2]) }
  ;

  BitwiseANDExprNoIn:
    EqualityExprNoIn
  | BitwiseANDExprNoIn '&' EqualityExprNoIn
                                        { result = BitAndNode.new(val[0], val[2]) }
  ;

  BitwiseANDExprNoBF:
    EqualityExprNoBF
  | BitwiseANDExprNoBF '&' EqualityExpr { result = BitAndNode.new(val[0], val[2]) }
  ;

  BitwiseXORExpr:
    BitwiseANDExpr
  | BitwiseXORExpr '^' BitwiseANDExpr   { result = BitXOrNode.new(val[0], val[2]) }
  ;

  BitwiseXORExprNoIn:
    BitwiseANDExprNoIn
  | BitwiseXORExprNoIn '^' BitwiseANDExprNoIn
                                        { result = BitXOrNode.new(val[0], val[2]) }
  ;

  BitwiseXORExprNoBF:
    BitwiseANDExprNoBF
  | BitwiseXORExprNoBF '^' BitwiseANDExpr
                                        { result = BitXOrNode.new(val[0], val[2]) }
  ;

  BitwiseORExpr:
    BitwiseXORExpr
  | BitwiseORExpr '|' BitwiseXORExpr    { result = BitOrNode.new(val[0], val[2]) }
  ;

  BitwiseORExprNoIn:
    BitwiseXORExprNoIn
  | BitwiseORExprNoIn '|' BitwiseXORExprNoIn
                                        { result = BitOrNode.new(val[0], val[2]) }
  ;

  BitwiseORExprNoBF:
    BitwiseXORExprNoBF
  | BitwiseORExprNoBF '|' BitwiseXORExpr
                                        { result = BitOrNode.new(val[0], val[2]) }
  ;

  LogicalANDExpr:
    BitwiseORExpr
  | LogicalANDExpr AND BitwiseORExpr    { result = LogicalAndNode.new(val[0], val[2]) }
  ;

  LogicalANDExprNoIn:
    BitwiseORExprNoIn
  | LogicalANDExprNoIn AND BitwiseORExprNoIn
                                        { result = LogicalAndNode.new(val[0], val[2]) }
  ;

  LogicalANDExprNoBF:
    BitwiseORExprNoBF
  | LogicalANDExprNoBF AND BitwiseORExpr
                                        { result = LogicalAndNode.new(val[0], val[2]) }
  ;

  LogicalORExpr:
    LogicalANDExpr
  | LogicalORExpr OR LogicalANDExpr     { result = LogicalOrNode.new(val[0], val[2]) }
  ;

  LogicalORExprNoIn:
    LogicalANDExprNoIn
  | LogicalORExprNoIn OR LogicalANDExprNoIn
                                        { result = LogicalOrNode.new(val[0], val[2]) }
  ;

  LogicalORExprNoBF:
    LogicalANDExprNoBF
  | LogicalORExprNoBF OR LogicalANDExpr { result = LogicalOrNode.new(val[0], val[2]) }
  ;

  ConditionalExpr:
    LogicalORExpr
  | LogicalORExpr '?' AssignmentExpr ':' AssignmentExpr {
      result = ConditionalNode.new(val[0], val[2], val[4])
    }
  ;

  ConditionalExprNoIn:
    LogicalORExprNoIn
  | LogicalORExprNoIn '?' AssignmentExprNoIn ':' AssignmentExprNoIn {
      result = ConditionalNode.new(val[0], val[2], val[4])
    }
  ;

  ConditionalExprNoBF:
    LogicalORExprNoBF
  | LogicalORExprNoBF '?' AssignmentExpr ':' AssignmentExpr {
      result = ConditionalNode.new(val[0], val[2], val[4])
    }
  ;

  AssignmentExpr:
    ConditionalExpr
  | LeftHandSideExpr AssignmentOperator AssignmentExpr {
      result = val[1].new(val.first, val.last)
    }
  ;

  AssignmentExprNoIn:
    ConditionalExprNoIn
  | LeftHandSideExpr AssignmentOperator AssignmentExprNoIn {
      result = val[1].new(val.first, val.last)
    }
  ;

  AssignmentExprNoBF:
    ConditionalExprNoBF
  | LeftHandSideExprNoBF AssignmentOperator AssignmentExpr {
      result = val[1].new(val.first, val.last)
    }
  ;

  AssignmentOperator:
    '='                                 { result = OpEqualNode }
  | PLUSEQUAL                           { result = OpPlusEqualNode }
  | MINUSEQUAL                          { result = OpMinusEqualNode }
  | MULTEQUAL                           { result = OpMultiplyEqualNode }
  | DIVEQUAL                            { result = OpDivideEqualNode }
  | LSHIFTEQUAL                         { result = OpLShiftEqualNode }
  | RSHIFTEQUAL                         { result = OpRShiftEqualNode }
  | URSHIFTEQUAL                        { result = OpURShiftEqualNode }
  | ANDEQUAL                            { result = OpAndEqualNode }
  | XOREQUAL                            { result = OpXOrEqualNode }
  | OREQUAL                             { result = OpOrEqualNode }
  | MODEQUAL                            { result = OpModEqualNode }
  ;

  Expr:
    AssignmentExpr
  | Expr ',' AssignmentExpr             { result = CommaNode.new(val[0], val[2]) }
  ;

  ExprNoIn:
    AssignmentExprNoIn
  | ExprNoIn ',' AssignmentExprNoIn     { result = CommaNode.new(val[0], val[2]) }
  ;

  ExprNoBF:
    AssignmentExprNoBF
  | ExprNoBF ',' AssignmentExpr       { result = CommaNode.new(val[0], val[2]) }
  ;


  Block:
    '{' SourceElements '}' {
      result = BlockNode.new(val[1])
      debug(result)
    }
  ;

  VariableStatement:
    VAR VariableDeclarationList ';' {
      result = VarStatementNode.new(val[1])
      debug(result)
    }
  | VAR VariableDeclarationList error {
      result = VarStatementNode.new(val[1])
      debug(result)
      yyabort unless allow_auto_semi?(val.last)
    }
  ;

  VariableDeclarationList:
    VariableDeclaration                 { result = val }
  | VariableDeclarationList ',' VariableDeclaration {
      result = [val.first, val.last].flatten
    }
  ;

  VariableDeclarationListNoIn:
    VariableDeclarationNoIn             { result = val }
  | VariableDeclarationListNoIn ',' VariableDeclarationNoIn {
      result = [val.first, val.last].flatten
    }
  ;

  VariableDeclaration:
    IDENT             { result = VarDeclNode.new(val.first, nil) }
  | IDENT Initializer { result = VarDeclNode.new(val.first, val[1]) }
  ;

  VariableDeclarationNoIn:
    IDENT                               { result = VarDeclNode.new(val[0],nil) }
  | IDENT InitializerNoIn               { result = VarDeclNode.new(val[0], val[1]) }
  ;

  ConstStatement:
    CONST ConstDeclarationList ';' {
      result = ConstStatementNode.new(val[1])
      debug(result)
    }
  | CONST ConstDeclarationList error {
      result = ConstStatementNode.new(val[1])
      debug(result)
      yyerror unless allow_auto_semi?(val.last)
    }
  ;

  ConstDeclarationList:
    ConstDeclaration                    { result = val }
  | ConstDeclarationList ',' ConstDeclaration {
      result = [val.first, val.last].flatten
    }
  ;

  ConstDeclaration:
    IDENT             { result = VarDeclNode.new(val[0], nil, true) }
  | IDENT Initializer { result = VarDeclNode.new(val[0], val[1], true) }
  ;

  Initializer:
    '=' AssignmentExpr                  { result = AssignExprNode.new(val[1]) }
  ;

  InitializerNoIn:
    '=' AssignmentExprNoIn              { result = AssignExprNode.new(val[1]) }
  ;

  EmptyStatement:
    ';' { result = EmptyStatementNode.new(val[0]) }
  ;

  ExprStatement:
    ExprNoBF ';' {
      result = ExpressionStatementNode.new(val.first)
      debug(result)
    }
  | ExprNoBF error {
      result = ExpressionStatementNode.new(val.first)
      debug(result)
      raise RKelly::SyntaxError unless allow_auto_semi?(val.last)
    }
  ;

  IfStatement:
    IF '(' Expr ')' Statement =IF_WITHOUT_ELSE {
      result = IfNode.new(val[2], val[4])
      debug(result)
    }
  | IF '(' Expr ')' Statement ELSE Statement {
      result = IfNode.new(val[2], val[4], val[6])
      debug(result)
    }
  ;

  IterationStatement:
    DO Statement WHILE '(' Expr ')' ';' {
      result = DoWhileNode.new(val[1], val[4])
      debug(result)
    }
  | DO Statement WHILE '(' Expr ')' error {
      result = DoWhileNode.new(val[1], val[4])
      debug(result)
    } /* Always performs automatic semicolon insertion. */
  | WHILE '(' Expr ')' Statement {
      result = WhileNode.new(val[2], val[4])
      debug(result)
    }
  | FOR '(' ExprNoInOpt ';' ExprOpt ';' ExprOpt ')' Statement {
      result = ForNode.new(val[2], val[4], val[6], val[8])
      debug(result)
    }
  | FOR '(' VAR VariableDeclarationListNoIn ';' ExprOpt ';' ExprOpt ')' Statement
    {
      result = ForNode.new(VarStatementNode.new(val[3]), val[5], val[7], val[9])
      debug(result)
    }
  | FOR '(' LeftHandSideExpr IN Expr ')' Statement {
      #yyabort if (!n.isLocation())
      result = ForInNode.new(val[2], val[4], val[6])
      debug(result);
    }
  | FOR '(' VAR IDENT IN Expr ')' Statement {
      result = ForInNode.new(
        VarDeclNode.new(val[3], nil), val[5], val[7])
      debug(result)
    }
  | FOR '(' VAR IDENT InitializerNoIn IN Expr ')' Statement {
      result = ForInNode.new(
        VarDeclNode.new(val[3], val[4]), val[6], val[8]
      )
      debug(result)
    }
  ;

  ExprOpt:
    /* nothing */                       { result = nil }
  | Expr
  ;

  ExprNoInOpt:
    /* nothing */                       { result = nil }
  | ExprNoIn
  ;

  ContinueStatement:
    CONTINUE ';' {
      result = ContinueNode.new(nil)
      debug(result)
    }
  | CONTINUE error {
      result = ContinueNode.new(nil)
      debug(result)
      yyabort unless allow_auto_semi?(val[1])
    }
  | CONTINUE IDENT ';' {
      result = ContinueNode.new(val[1])
      debug(result)
    }
  | CONTINUE IDENT error {
      result = ContinueNode.new(val[1])
      debug(result)
      yyabort unless allow_auto_semi?(val[2])
    }
  ;

  BreakStatement:
    BREAK ';' {
      result = BreakNode.new(nil)
      debug(result)
    }
  | BREAK error {
      result = BreakNode.new(nil)
      debug(result)
      yyabort unless allow_auto_semi?(val[1])
    }
  | BREAK IDENT ';' {
      result = BreakNode.new(val[1])
      debug(result)
    }
  | BREAK IDENT error {
      result = BreakNode.new(val[1])
      debug(result)
      yyabort unless allow_auto_semi?(val[2])
    }
  ;

  ReturnStatement:
    RETURN ';' {
      result = ReturnNode.new(nil)
      debug(result)
    }
  | RETURN error {
      result = ReturnNode.new(nil)
      debug(result)
      yyabort unless allow_auto_semi?(val[1])
    }
  | RETURN Expr ';' {
      result = ReturnNode.new(val[1])
      debug(result)
    }
  | RETURN Expr error {
      result = ReturnNode.new(val[1])
      debug(result)
      yyabort unless allow_auto_semi?(val[2])
    }
  ;

  WithStatement:
    WITH '(' Expr ')' Statement {
      result = WithNode.new(val[2], val[4])
      debug(result)
    }
  ;

  SwitchStatement:
    SWITCH '(' Expr ')' CaseBlock {
      result = SwitchNode.new(val[2], val[4])
      debug(result)
    }
  ;

  CaseBlock:
    '{' CaseClausesOpt '}'              { result = CaseBlockNode.new(val[1]) }
  | '{' CaseClausesOpt DefaultClause CaseClausesOpt '}' {
      result = CaseBlockNode.new([val[1], val[2], val[3]].flatten)
    }
  ;

  CaseClausesOpt:
    /* nothing */                       { result = [] }
  | CaseClauses
  ;

  CaseClauses:
    CaseClause                          { result = val }
  | CaseClauses CaseClause              { result = val.flatten }
  ;

  CaseClause:
    CASE Expr ':' SourceElements        {
      result = CaseClauseNode.new(val[1], val[3])
    }
  ;

  DefaultClause:
    DEFAULT ':' SourceElements          {
      result = CaseClauseNode.new(nil, val[2])
    }
  ;

  LabelledStatement:
    IDENT ':' Statement { result = LabelNode.new(val[0], val[2]) }
  ;

  ThrowStatement:
    THROW Expr ';' {
      result = ThrowNode.new(val[1])
      debug(result)
    }
  | THROW Expr error {
      result = ThrowNode.new(val[1])
      debug(result)
      yyabort unless allow_auto_semi?(val[2])
    }
  ;

  TryStatement:
    TRY Block FINALLY Block {
      result = TryNode.new(val[1], nil, nil, val[3])
      debug(result)
    }
  | TRY Block CATCH '(' IDENT ')' Block {
      result = TryNode.new(val[1], val[4], val[6])
      debug(result)
    }
  | TRY Block CATCH '(' IDENT ')' Block FINALLY Block {
      result = TryNode.new(val[1], val[4], val[6], val[8])
      debug(result)
    }
  ;

  DebuggerStatement:
    DEBUGGER ';' {
      result = EmptyStatementNode.new(val[0])
      debug(result)
    }
  | DEBUGGER error {
      result = EmptyStatementNode.new(val[0])
      debug(result)
      yyabort unless allow_auto_semi?(val[1])
    }
  ;

  FunctionDeclaration:
    FUNCTION IDENT '(' ')' FunctionBody {
      result = FunctionDeclNode.new(val[1], val[4])
      debug(val[5])
    }
  | FUNCTION IDENT '(' FormalParameterList ')' FunctionBody {
      result = FunctionDeclNode.new(val[1], val[5], val[3])
      debug(val[6])
    }
  ;

  FunctionExpr:
    FUNCTION '(' ')' FunctionBody {
      result = FunctionExprNode.new(val[0], val[3])
      debug(val[4])
    }
  | FUNCTION '(' FormalParameterList ')' FunctionBody {
      result = FunctionExprNode.new(val[0], val[4], val[2])
      debug(val[5])
    }
  | FUNCTION IDENT '(' ')' FunctionBody {
      result = FunctionExprNode.new(val[1], val[4])
      debug(val[5])
    }
  | FUNCTION IDENT '(' FormalParameterList ')' FunctionBody {
      result = FunctionExprNode.new(val[1], val[5], val[3])
      debug(val[6])
    }
  ;

  FormalParameterList:
    IDENT                               { result = [ParameterNode.new(val[0])] }
  | FormalParameterList ',' IDENT       {
      result = [val.first, ParameterNode.new(val.last)].flatten
    }
  ;

  FunctionBody:
    '{' SourceElements '}'              { result = FunctionBodyNode.new(val[1]) }
  ;
end

---- header
  require "rkelly/nodes"

---- inner
  include RKelly::Nodes

  def allow_auto_semi?(error_token)
    error_token == false || error_token == '}' || @terminator
  end

  def property_class_for(ident)
    case ident
    when 'get'
      GetterPropertyNode
    when 'set'
      SetterPropertyNode
    end
  end

  def debug(*args)
    logger.debug(*args) if logger
  end
