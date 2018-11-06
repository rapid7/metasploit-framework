module CodeRay
module Scanners
  
  # Scanner for JavaScript.
  # 
  # Aliases: +ecmascript+, +ecma_script+, +javascript+
  class JavaScript < Scanner
    
    register_for :java_script
    file_extension 'js'
    
    # The actual JavaScript keywords.
    KEYWORDS = %w[
      break case catch continue default delete do else
      finally for function if in instanceof new
      return switch throw try typeof var void while with
    ]  # :nodoc:
    PREDEFINED_CONSTANTS = %w[
      false null true undefined NaN Infinity
    ]  # :nodoc:
    
    MAGIC_VARIABLES = %w[ this arguments ]  # :nodoc: arguments was introduced in JavaScript 1.4
    
    KEYWORDS_EXPECTING_VALUE = WordList.new.add %w[
      case delete in instanceof new return throw typeof with
    ]  # :nodoc:
    
    # Reserved for future use.
    RESERVED_WORDS = %w[
      abstract boolean byte char class debugger double enum export extends
      final float goto implements import int interface long native package
      private protected public short static super synchronized throws transient
      volatile
    ]  # :nodoc:
    
    IDENT_KIND = WordList.new(:ident).
      add(RESERVED_WORDS, :reserved).
      add(PREDEFINED_CONSTANTS, :predefined_constant).
      add(MAGIC_VARIABLES, :local_variable).
      add(KEYWORDS, :keyword)  # :nodoc:
    
    ESCAPE = / [bfnrtv\n\\'"] | x[a-fA-F0-9]{1,2} | [0-7]{1,3} /x  # :nodoc:
    UNICODE_ESCAPE =  / u[a-fA-F0-9]{4} | U[a-fA-F0-9]{8} /x  # :nodoc:
    REGEXP_ESCAPE =  / [bBdDsSwW] /x  # :nodoc:
    STRING_CONTENT_PATTERN = {
      "'" => /[^\\']+/,
      '"' => /[^\\"]+/,
      '/' => /[^\\\/]+/,
    }  # :nodoc:
    KEY_CHECK_PATTERN = {
      "'" => / (?> [^\\']* (?: \\. [^\\']* )* ) ' \s* : /mx,
      '"' => / (?> [^\\"]* (?: \\. [^\\"]* )* ) " \s* : /mx,
    }  # :nodoc:
    
  protected
    
    def setup
      @state = :initial
    end
    
    def scan_tokens encoder, options
      
      state, string_delimiter = options[:state] || @state
      if string_delimiter
        encoder.begin_group state
      end
      
      value_expected = true
      key_expected = false
      function_expected = false
      
      until eos?
        
        case state
          
        when :initial
          
          if match = scan(/ \s+ | \\\n /x)
            value_expected = true if !value_expected && match.index(?\n)
            encoder.text_token match, :space
            
          elsif match = scan(%r! // [^\n\\]* (?: \\. [^\n\\]* )* | /\* (?: .*? \*/ | .*() ) !mx)
            value_expected = true
            encoder.text_token match, :comment
            state = :open_multi_line_comment if self[1]
            
          elsif check(/\.?\d/)
            key_expected = value_expected = false
            if match = scan(/0[xX][0-9A-Fa-f]+/)
              encoder.text_token match, :hex
            elsif match = scan(/(?>0[0-7]+)(?![89.eEfF])/)
              encoder.text_token match, :octal
            elsif match = scan(/\d+[fF]|\d*\.\d+(?:[eE][+-]?\d+)?[fF]?|\d+[eE][+-]?\d+[fF]?/)
              encoder.text_token match, :float
            elsif match = scan(/\d+/)
              encoder.text_token match, :integer
            end
            
          elsif value_expected && match = scan(/<([[:alpha:]]\w*) (?: [^\/>]*\/> | .*?<\/\1>)/xim)
            # TODO: scan over nested tags
            xml_scanner.tokenize match, :tokens => encoder
            value_expected = false
            next
            
          elsif match = scan(/ [-+*=<>?:;,!&^|(\[{~%]+ | \.(?!\d) /x)
            value_expected = true
            last_operator = match[-1]
            key_expected = (last_operator == ?{) || (last_operator == ?,)
            function_expected = false
            encoder.text_token match, :operator
            
          elsif match = scan(/ [)\]}]+ /x)
            function_expected = key_expected = value_expected = false
            encoder.text_token match, :operator
            
          elsif match = scan(/ [$a-zA-Z_][A-Za-z_0-9$]* /x)
            kind = IDENT_KIND[match]
            value_expected = (kind == :keyword) && KEYWORDS_EXPECTING_VALUE[match]
            # TODO: labels
            if kind == :ident
              if match.index(?$)  # $ allowed inside an identifier
                kind = :predefined
              elsif function_expected
                kind = :function
              elsif check(/\s*[=:]\s*function\b/)
                kind = :function
              elsif key_expected && check(/\s*:/)
                kind = :key
              end
            end
            function_expected = (kind == :keyword) && (match == 'function')
            key_expected = false
            encoder.text_token match, kind
            
          elsif match = scan(/["']/)
            if key_expected && check(KEY_CHECK_PATTERN[match])
              state = :key
            else
              state = :string
            end
            encoder.begin_group state
            string_delimiter = match
            encoder.text_token match, :delimiter
            
          elsif value_expected && (match = scan(/\//))
            encoder.begin_group :regexp
            state = :regexp
            string_delimiter = '/'
            encoder.text_token match, :delimiter
            
          elsif match = scan(/ \/ /x)
            value_expected = true
            key_expected = false
            encoder.text_token match, :operator
            
          else
            encoder.text_token getch, :error
            
          end
          
        when :string, :regexp, :key
          if match = scan(STRING_CONTENT_PATTERN[string_delimiter])
            encoder.text_token match, :content
          elsif match = scan(/["'\/]/)
            encoder.text_token match, :delimiter
            if state == :regexp
              modifiers = scan(/[gim]+/)
              encoder.text_token modifiers, :modifier if modifiers && !modifiers.empty?
            end
            encoder.end_group state
            string_delimiter = nil
            key_expected = value_expected = false
            state = :initial
          elsif state != :regexp && (match = scan(/ \\ (?: #{ESCAPE} | #{UNICODE_ESCAPE} ) /mox))
            if string_delimiter == "'" && !(match == "\\\\" || match == "\\'")
              encoder.text_token match, :content
            else
              encoder.text_token match, :char
            end
          elsif state == :regexp && match = scan(/ \\ (?: #{ESCAPE} | #{REGEXP_ESCAPE} | #{UNICODE_ESCAPE} ) /mox)
            encoder.text_token match, :char
          elsif match = scan(/\\./m)
            encoder.text_token match, :content
          elsif match = scan(/ \\ | $ /x)
            encoder.end_group state
            encoder.text_token match, :error unless match.empty?
            string_delimiter = nil
            key_expected = value_expected = false
            state = :initial
          else
            raise_inspect "else case #{string_delimiter} reached; %p not handled." % peek(1), encoder
          end
          
        when :open_multi_line_comment
          if match = scan(%r! .*? \*/ !mx)
            state = :initial
          else
            match = scan(%r! .+ !mx)
          end
          value_expected = true
          encoder.text_token match, :comment if match
          
        else
          #:nocov:
          raise_inspect 'Unknown state: %p' % [state], encoder
          #:nocov:
          
        end
        
      end
      
      if options[:keep_state]
        @state = state, string_delimiter
      end
      
      if [:string, :regexp].include? state
        encoder.end_group state
      end
      
      encoder
    end
    
  protected
    
    def reset_instance
      super
      @xml_scanner.reset if defined? @xml_scanner
    end
    
    def xml_scanner
      @xml_scanner ||= CodeRay.scanner :xml, :tokens => @tokens, :keep_tokens => true, :keep_state => false
    end
    
  end
  
end
end
