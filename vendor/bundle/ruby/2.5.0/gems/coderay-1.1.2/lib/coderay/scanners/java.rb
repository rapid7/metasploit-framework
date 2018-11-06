module CodeRay
module Scanners
  
  # Scanner for Java.
  class Java < Scanner
    
    register_for :java
    
    autoload :BuiltinTypes, CodeRay.coderay_path('scanners', 'java', 'builtin_types')
    
    # http://java.sun.com/docs/books/tutorial/java/nutsandbolts/_keywords.html
    KEYWORDS = %w[
      assert break case catch continue default do else
      finally for if instanceof import new package
      return switch throw try typeof while
      debugger export
    ]  # :nodoc:
    RESERVED = %w[ const goto ]  # :nodoc:
    CONSTANTS = %w[ false null true ]  # :nodoc:
    MAGIC_VARIABLES = %w[ this super ]  # :nodoc:
    TYPES = %w[
      boolean byte char class double enum float int interface long
      short void
    ] << '[]'  # :nodoc: because int[] should be highlighted as a type
    DIRECTIVES = %w[
      abstract extends final implements native private protected public
      static strictfp synchronized throws transient volatile
    ]  # :nodoc:
    
    IDENT_KIND = WordList.new(:ident).
      add(KEYWORDS, :keyword).
      add(RESERVED, :reserved).
      add(CONSTANTS, :predefined_constant).
      add(MAGIC_VARIABLES, :local_variable).
      add(TYPES, :type).
      add(BuiltinTypes::List, :predefined_type).
      add(BuiltinTypes::List.select { |builtin| builtin[/(Error|Exception)$/] }, :exception).
      add(DIRECTIVES, :directive)  # :nodoc:
    
    ESCAPE = / [bfnrtv\n\\'"] | x[a-fA-F0-9]{1,2} | [0-7]{1,3} /x  # :nodoc:
    UNICODE_ESCAPE =  / u[a-fA-F0-9]{4} | U[a-fA-F0-9]{8} /x  # :nodoc:
    STRING_CONTENT_PATTERN = {
      "'" => /[^\\']+/,
      '"' => /[^\\"]+/,
      '/' => /[^\\\/]+/,
    }  # :nodoc:
    IDENT = RUBY_VERSION < '1.9' ? /[a-zA-Z_][A-Za-z_0-9]*/ : Regexp.new('[[[:alpha:]]_][[[:alnum:]]_]*')  # :nodoc:
    
  protected
    
    def scan_tokens encoder, options

      state = :initial
      string_delimiter = nil
      package_name_expected = false
      class_name_follows = false
      last_token_dot = false

      until eos?

        case state

        when :initial

          if match = scan(/ \s+ | \\\n /x)
            encoder.text_token match, :space
            next
          
          elsif match = scan(%r! // [^\n\\]* (?: \\. [^\n\\]* )* | /\* (?: .*? \*/ | .* ) !mx)
            encoder.text_token match, :comment
            next
          
          elsif package_name_expected && match = scan(/ #{IDENT} (?: \. #{IDENT} )* /ox)
            encoder.text_token match, package_name_expected
          
          elsif match = scan(/ #{IDENT} | \[\] /ox)
            kind = IDENT_KIND[match]
            if last_token_dot
              kind = :ident
            elsif class_name_follows
              kind = :class
              class_name_follows = false
            else
              case match
              when 'import'
                package_name_expected = :include
              when 'package'
                package_name_expected = :namespace
              when 'class', 'interface'
                class_name_follows = true
              end
            end
            encoder.text_token match, kind
          
          elsif match = scan(/ \.(?!\d) | [,?:()\[\]}] | -- | \+\+ | && | \|\| | \*\*=? | [-+*\/%^~&|<>=!]=? | <<<?=? | >>>?=? /x)
            encoder.text_token match, :operator
          
          elsif match = scan(/;/)
            package_name_expected = false
            encoder.text_token match, :operator
          
          elsif match = scan(/\{/)
            class_name_follows = false
            encoder.text_token match, :operator
          
          elsif check(/[\d.]/)
            if match = scan(/0[xX][0-9A-Fa-f]+/)
              encoder.text_token match, :hex
            elsif match = scan(/(?>0[0-7]+)(?![89.eEfF])/)
              encoder.text_token match, :octal
            elsif match = scan(/\d+[fFdD]|\d*\.\d+(?:[eE][+-]?\d+)?[fFdD]?|\d+[eE][+-]?\d+[fFdD]?/)
              encoder.text_token match, :float
            elsif match = scan(/\d+[lL]?/)
              encoder.text_token match, :integer
            end

          elsif match = scan(/["']/)
            state = :string
            encoder.begin_group state
            string_delimiter = match
            encoder.text_token match, :delimiter

          elsif match = scan(/ @ #{IDENT} /ox)
            encoder.text_token match, :annotation

          else
            encoder.text_token getch, :error

          end

        when :string
          if match = scan(STRING_CONTENT_PATTERN[string_delimiter])
            encoder.text_token match, :content
          elsif match = scan(/["'\/]/)
            encoder.text_token match, :delimiter
            encoder.end_group state
            state = :initial
            string_delimiter = nil
          elsif state == :string && (match = scan(/ \\ (?: #{ESCAPE} | #{UNICODE_ESCAPE} ) /mox))
            if string_delimiter == "'" && !(match == "\\\\" || match == "\\'")
              encoder.text_token match, :content
            else
              encoder.text_token match, :char
            end
          elsif match = scan(/\\./m)
            encoder.text_token match, :content
          elsif match = scan(/ \\ | $ /x)
            encoder.end_group state
            state = :initial
            encoder.text_token match, :error unless match.empty?
          else
            raise_inspect "else case \" reached; %p not handled." % peek(1), encoder
          end

        else
          raise_inspect 'Unknown state', encoder

        end
        
        last_token_dot = match == '.'
        
      end

      if state == :string
        encoder.end_group state
      end

      encoder
    end

  end

end
end
