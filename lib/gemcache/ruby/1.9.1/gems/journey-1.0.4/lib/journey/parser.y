class Journey::Parser

token SLASH LITERAL SYMBOL LPAREN RPAREN DOT STAR OR

rule
  expressions
    : expressions expression  { result = Cat.new(val.first, val.last) }
    | expression              { result = val.first }
    | or
    ;
  expression
    : terminal
    | group
    | star
    ;
  group
    : LPAREN expressions RPAREN { result = Group.new(val[1]) }
    ;
  or
    : expressions OR expression { result = Or.new([val.first, val.last]) }
    ;
  star
    : STAR literal       { result = Star.new(Symbol.new(val.last.left)) }
    ;
  terminal
    : symbol
    | literal
    | slash
    | dot
    ;
  slash
    : SLASH              { result = Slash.new('/') }
    ;
  symbol
    : SYMBOL             { result = Symbol.new(val.first) }
    ;
  literal
    : LITERAL            { result = Literal.new(val.first) }
  dot
    : DOT                { result = Dot.new(val.first) }
    ;

end

---- header

require 'journey/parser_extras'
