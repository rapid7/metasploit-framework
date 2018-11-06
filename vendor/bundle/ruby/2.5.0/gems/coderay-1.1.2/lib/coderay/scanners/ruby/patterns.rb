# encoding: utf-8
module CodeRay
module Scanners
  
  module Ruby::Patterns  # :nodoc: all
    
    KEYWORDS = %w[
      and def end in or unless begin
      defined? ensure module redo super until
      BEGIN break do next rescue then
      when END case else for retry
      while alias class elsif if not return
      undef yield
    ]
    
    # See http://murfy.de/ruby-constants.
    PREDEFINED_CONSTANTS = %w[
      nil true false self
      DATA ARGV ARGF ENV
      FALSE TRUE NIL
      STDERR STDIN STDOUT
      TOPLEVEL_BINDING
      RUBY_COPYRIGHT RUBY_DESCRIPTION RUBY_ENGINE RUBY_PATCHLEVEL
      RUBY_PLATFORM RUBY_RELEASE_DATE RUBY_REVISION RUBY_VERSION
      __FILE__ __LINE__ __ENCODING__
    ]
    
    IDENT_KIND = WordList.new(:ident).
      add(KEYWORDS, :keyword).
      add(PREDEFINED_CONSTANTS, :predefined_constant)
    
    KEYWORD_NEW_STATE = WordList.new(:initial).
      add(%w[ def ], :def_expected).
      add(%w[ undef ], :undef_expected).
      add(%w[ alias ], :alias_expected).
      add(%w[ class module ], :module_expected)
    
    IDENT = 'ä'[/[[:alpha:]]/] == 'ä' ? Regexp.new('[[:alpha:]_[^\0-\177]][[:alnum:]_[^\0-\177]]*') : /[^\W\d]\w*/
    
    METHOD_NAME = / #{IDENT} [?!]? /ox
    METHOD_NAME_OPERATOR = /
      \*\*?           # multiplication and power
      | [-+~]@?       # plus, minus, tilde with and without at sign
      | [\/%&|^`]     # division, modulo or format strings, and, or, xor, system
      | \[\]=?        # array getter and setter
      | << | >>       # append or shift left, shift right
      | <=?>? | >=?   # comparison, rocket operator
      | ===? | =~     # simple equality, case equality, match
      | ![~=@]?       # negation with and without at sign, not-equal and not-match
    /ox
    METHOD_SUFFIX = / (?: [?!] | = (?![~>]|=(?!>)) ) /x
    METHOD_NAME_EX = / #{IDENT} #{METHOD_SUFFIX}? | #{METHOD_NAME_OPERATOR} /ox
    METHOD_AFTER_DOT = / #{IDENT} [?!]? | #{METHOD_NAME_OPERATOR} /ox
    INSTANCE_VARIABLE = / @ #{IDENT} /ox
    CLASS_VARIABLE = / @@ #{IDENT} /ox
    OBJECT_VARIABLE = / @@? #{IDENT} /ox
    GLOBAL_VARIABLE = / \$ (?: #{IDENT} | [1-9]\d* | 0\w* | [~&+`'=\/,;_.<>!@$?*":\\] | -[a-zA-Z_0-9] ) /ox
    PREFIX_VARIABLE = / #{GLOBAL_VARIABLE} | #{OBJECT_VARIABLE} /ox
    VARIABLE = / @?@? #{IDENT} | #{GLOBAL_VARIABLE} /ox
    
    QUOTE_TO_TYPE = {
      '`' => :shell,
      '/'=> :regexp,
    }
    QUOTE_TO_TYPE.default = :string
    
    REGEXP_MODIFIERS = /[mousenix]*/
    
    DECIMAL = /\d+(?:_\d+)*/
    OCTAL = /0_?[0-7]+(?:_[0-7]+)*/
    HEXADECIMAL = /0x[0-9A-Fa-f]+(?:_[0-9A-Fa-f]+)*/
    BINARY = /0b[01]+(?:_[01]+)*/
    
    EXPONENT = / [eE] [+-]? #{DECIMAL} /ox
    FLOAT_SUFFIX = / #{EXPONENT} | \. #{DECIMAL} #{EXPONENT}? /ox
    FLOAT_OR_INT = / #{DECIMAL} (?: #{FLOAT_SUFFIX} () )? /ox
    NUMERIC = / (?: (?=0) (?: #{OCTAL} | #{HEXADECIMAL} | #{BINARY} ) | #{FLOAT_OR_INT} ) /ox
    
    SYMBOL = /
      :
      (?:
        #{METHOD_NAME_EX}
      | #{PREFIX_VARIABLE}
      | ['"]
      )
    /ox
    METHOD_NAME_OR_SYMBOL = / #{METHOD_NAME_EX} | #{SYMBOL} /ox
    
    SIMPLE_ESCAPE = /
        [abefnrstv]
      |  [0-7]{1,3}
      | x[0-9A-Fa-f]{1,2}
      | .
    /mx
    
    CONTROL_META_ESCAPE = /
      (?: M-|C-|c )
      (?: \\ (?: M-|C-|c ) )*
      (?: [^\\] | \\ #{SIMPLE_ESCAPE} )?
    /mox
    
    ESCAPE = /
      #{CONTROL_META_ESCAPE} | #{SIMPLE_ESCAPE}
    /mox
    
    CHARACTER = /
      \?
      (?:
        [^\s\\]
      | \\ #{ESCAPE}
      )
    /mox
    
    # NOTE: This is not completely correct, but
    # nobody needs heredoc delimiters ending with \n.
    HEREDOC_OPEN = /
      << ([-~])?           # $1 = float
      (?:
        ( [A-Za-z_0-9]+ )  # $2 = delim
      |
        ( ["'`\/] )        # $3 = quote, type
        ( [^\n]*? ) \3     # $4 = delim
      )
    /mx
    
    RUBYDOC = /
      =begin (?!\S)
      .*?
      (?: \Z | ^=end (?!\S) [^\n]* )
    /mx
    
    DATA = /
      __END__$
      .*?
      (?: \Z | (?=^\#CODE) )
    /mx
    
    RUBYDOC_OR_DATA = / #{RUBYDOC} | #{DATA} /xo
    
    # Checks for a valid value to follow. This enables
    # value_expected in method calls without parentheses.
    VALUE_FOLLOWS = /
      (?>[ \t\f\v]+)
      (?:
        [%\/][^\s=]
      | <<-?\S
      | [-+] \d
      | #{CHARACTER}
      )
    /ox
    KEYWORDS_EXPECTING_VALUE = WordList.new.add(%w[
      and end in or unless begin
      defined? ensure redo super until
      break do next rescue then
      when case else for retry
      while elsif if not return
      yield
    ])
    
    FANCY_STRING_START = / % ( [iIqQrswWx] | (?![a-zA-Z0-9]) ) ([^a-zA-Z0-9]) /x
    FANCY_STRING_KIND = Hash.new(:string).merge({
      'i' => :symbol,
      'I' => :symbol,
      'r' => :regexp,
      's' => :symbol,
      'x' => :shell,
    })
    FANCY_STRING_INTERPRETED = Hash.new(true).merge({
      'i' => false,
      'q' => false,
      's' => false,
      'w' => false,
    })
    
  end
  
end
end
