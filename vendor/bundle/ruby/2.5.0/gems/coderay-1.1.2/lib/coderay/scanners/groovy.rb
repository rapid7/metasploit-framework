module CodeRay
module Scanners
  
  load :java
  
  # Scanner for Groovy.
  class Groovy < Java
    
    register_for :groovy
    
    # TODO: check list of keywords
    GROOVY_KEYWORDS = %w[
      as assert def in
    ]  # :nodoc:
    KEYWORDS_EXPECTING_VALUE = WordList.new.add %w[
      case instanceof new return throw typeof while as assert in
    ]  # :nodoc:
    GROOVY_MAGIC_VARIABLES = %w[ it ]  # :nodoc:
    
    IDENT_KIND = Java::IDENT_KIND.dup.
      add(GROOVY_KEYWORDS, :keyword).
      add(GROOVY_MAGIC_VARIABLES, :local_variable)  # :nodoc:
    
    ESCAPE = / [bfnrtv$\n\\'"] | x[a-fA-F0-9]{1,2} | [0-7]{1,3} /x  # :nodoc:
    UNICODE_ESCAPE =  / u[a-fA-F0-9]{4} /x  # :nodoc: no 4-byte unicode chars? U[a-fA-F0-9]{8}
    REGEXP_ESCAPE =  / [bfnrtv\n\\'"] | x[a-fA-F0-9]{1,2} | [0-7]{1,3} | \d | [bBdDsSwW\/] /x  # :nodoc:
    
    # TODO: interpretation inside ', ", /
    STRING_CONTENT_PATTERN = {
      "'" => /(?>\\[^\\'\n]+|[^\\'\n]+)+/,
      '"' => /[^\\$"\n]+/,
      "'''" => /(?>[^\\']+|'(?!''))+/,
      '"""' => /(?>[^\\$"]+|"(?!""))+/,
      '/' => /[^\\$\/\n]+/,
    }  # :nodoc:
    
  protected
    
    def setup
      @state = :initial
    end
    
    def scan_tokens encoder, options
      state = options[:state] || @state
      inline_block_stack = []
      inline_block_paren_depth = nil
      string_delimiter = nil
      import_clause = class_name_follows = last_token = after_def = false
      value_expected = true
      
      until eos?
        
        case state
        
        when :initial
          
          if match = scan(/ \s+ | \\\n /x)
            encoder.text_token match, :space
            if match.index ?\n
              import_clause = after_def = false
              value_expected = true unless value_expected
            end
            next
          
          elsif match = scan(%r! // [^\n\\]* (?: \\. [^\n\\]* )* | /\* (?: .*? \*/ | .* ) !mx)
            value_expected = true
            after_def = false
            encoder.text_token match, :comment
          
          elsif bol? && match = scan(/ \#!.* /x)
            encoder.text_token match, :doctype
          
          elsif import_clause && match = scan(/ (?!as) #{IDENT} (?: \. #{IDENT} )* (?: \.\* )? /ox)
            after_def = value_expected = false
            encoder.text_token match, :include
          
          elsif match = scan(/ #{IDENT} | \[\] /ox)
            kind = IDENT_KIND[match]
            value_expected = (kind == :keyword) && KEYWORDS_EXPECTING_VALUE[match]
            if last_token == '.'
              kind = :ident
            elsif class_name_follows
              kind = :class
              class_name_follows = false
            elsif after_def && check(/\s*[({]/)
              kind = :method
              after_def = false
            elsif kind == :ident && last_token != '?' && check(/:/)
              kind = :key
            else
              class_name_follows = true if match == 'class' || (import_clause && match == 'as')
              import_clause = match == 'import'
              after_def = true if match == 'def'
            end
            encoder.text_token match, kind
          
          elsif match = scan(/;/)
            import_clause = after_def = false
            value_expected = true
            encoder.text_token match, :operator
          
          elsif match = scan(/\{/)
            class_name_follows = after_def = false
            value_expected = true
            encoder.text_token match, :operator
            if !inline_block_stack.empty?
              inline_block_paren_depth += 1
            end
          
          # TODO: ~'...', ~"..." and ~/.../ style regexps
          elsif match = scan(/ \.\.<? | \*?\.(?!\d)@? | \.& | \?:? | [,?:(\[] | -[->] | \+\+ |
              && | \|\| | \*\*=? | ==?~ | <=?>? | [-+*%^~&|>=!]=? | <<<?=? | >>>?=? /x)
            value_expected = true
            value_expected = :regexp if match == '~'
            after_def = false
            encoder.text_token match, :operator
          
          elsif match = scan(/ [)\]}] /x)
            value_expected = after_def = false
            if !inline_block_stack.empty? && match == '}'
              inline_block_paren_depth -= 1
              if inline_block_paren_depth == 0  # closing brace of inline block reached
                encoder.text_token match, :inline_delimiter
                encoder.end_group :inline
                state, string_delimiter, inline_block_paren_depth = inline_block_stack.pop
                next
              end
            end
            encoder.text_token match, :operator
          
          elsif check(/[\d.]/)
            after_def = value_expected = false
            if match = scan(/0[xX][0-9A-Fa-f]+/)
              encoder.text_token match, :hex
            elsif match = scan(/(?>0[0-7]+)(?![89.eEfF])/)
              encoder.text_token match, :octal
            elsif match = scan(/\d+[fFdD]|\d*\.\d+(?:[eE][+-]?\d+)?[fFdD]?|\d+[eE][+-]?\d+[fFdD]?/)
              encoder.text_token match, :float
            elsif match = scan(/\d+[lLgG]?/)
              encoder.text_token match, :integer
            end
            
          elsif match = scan(/'''|"""/)
            after_def = value_expected = false
            state = :multiline_string
            encoder.begin_group :string
            string_delimiter = match
            encoder.text_token match, :delimiter
            
          # TODO: record.'name' syntax
          elsif match = scan(/["']/)
            after_def = value_expected = false
            state = match == '/' ? :regexp : :string
            encoder.begin_group state
            string_delimiter = match
            encoder.text_token match, :delimiter
            
          elsif value_expected && match = scan(/\//)
            after_def = value_expected = false
            encoder.begin_group :regexp
            state = :regexp
            string_delimiter = '/'
            encoder.text_token match, :delimiter
            
          elsif match = scan(/ @ #{IDENT} /ox)
            after_def = value_expected = false
            encoder.text_token match, :annotation
            
          elsif match = scan(/\//)
            after_def = false
            value_expected = true
            encoder.text_token match, :operator
            
          else
            encoder.text_token getch, :error
            
          end
          
        when :string, :regexp, :multiline_string
          if match = scan(STRING_CONTENT_PATTERN[string_delimiter])
            encoder.text_token match, :content
            
          elsif match = scan(state == :multiline_string ? /'''|"""/ : /["'\/]/)
            encoder.text_token match, :delimiter
            if state == :regexp
              # TODO: regexp modifiers? s, m, x, i?
              modifiers = scan(/[ix]+/)
              encoder.text_token modifiers, :modifier if modifiers && !modifiers.empty?
            end
            state = :string if state == :multiline_string
            encoder.end_group state
            string_delimiter = nil
            after_def = value_expected = false
            state = :initial
            next
            
          elsif (state == :string || state == :multiline_string) &&
              (match = scan(/ \\ (?: #{ESCAPE} | #{UNICODE_ESCAPE} ) /mox))
            if string_delimiter[0] == ?' && !(match == "\\\\" || match == "\\'")
              encoder.text_token match, :content
            else
              encoder.text_token match, :char
            end
          elsif state == :regexp && match = scan(/ \\ (?: #{REGEXP_ESCAPE} | #{UNICODE_ESCAPE} ) /mox)
            encoder.text_token match, :char
            
          elsif match = scan(/ \$ #{IDENT} /mox)
            encoder.begin_group :inline
            encoder.text_token '$', :inline_delimiter
            match = match[1..-1]
            encoder.text_token match, IDENT_KIND[match]
            encoder.end_group :inline
            next
          elsif match = scan(/ \$ \{ /x)
            encoder.begin_group :inline
            encoder.text_token match, :inline_delimiter
            inline_block_stack << [state, string_delimiter, inline_block_paren_depth]
            inline_block_paren_depth = 1
            state = :initial
            next
            
          elsif match = scan(/ \$ /mx)
            encoder.text_token match, :content
            
          elsif match = scan(/ \\. /mx)
            encoder.text_token match, :content  # TODO: Shouldn't this be :error?
            
          elsif match = scan(/ \\ | \n /x)
            encoder.end_group state == :regexp ? :regexp : :string
            encoder.text_token match, :error
            after_def = value_expected = false
            state = :initial
            
          else
            raise_inspect "else case \" reached; %p not handled." % peek(1), encoder
            
          end
          
        else
          raise_inspect 'Unknown state', encoder
          
        end
        
        last_token = match unless [:space, :comment, :doctype].include? kind
        
      end
      
      if [:multiline_string, :string, :regexp].include? state
        encoder.end_group state == :regexp ? :regexp : :string
      end
      
      if options[:keep_state]
        @state = state
      end
      
      until inline_block_stack.empty?
        state, = *inline_block_stack.pop
        encoder.end_group :inline
        encoder.end_group state == :regexp ? :regexp : :string
      end
      
      encoder
    end
    
  end
  
end
end
