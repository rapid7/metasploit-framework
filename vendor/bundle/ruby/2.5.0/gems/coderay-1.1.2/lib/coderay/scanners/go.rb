module CodeRay
module Scanners
  
  class Go < Scanner
    
    register_for :go
    file_extension 'go'
    
    # http://golang.org/ref/spec#Keywords
    KEYWORDS = [
      'break', 'default', 'func', 'interface', 'select',
      'case', 'defer', 'go', 'map', 'struct',
      'chan', 'else', 'goto', 'package', 'switch',
      'const', 'fallthrough', 'if', 'range', 'type',
      'continue', 'for', 'import', 'return', 'var',
    ]  # :nodoc:
    
    # http://golang.org/ref/spec#Types
    PREDEFINED_TYPES = [
      'bool',
      'uint8', 'uint16', 'uint32', 'uint64',
      'int8', 'int16', 'int32', 'int64',
      'float32', 'float64',
      'complex64', 'complex128',
      'byte', 'rune', 'string', 'error',
      'uint', 'int', 'uintptr',
    ]  # :nodoc:
    
    PREDEFINED_CONSTANTS = [
      'nil', 'iota',
      'true', 'false',
    ]  # :nodoc:
    
    PREDEFINED_FUNCTIONS = %w[
      append cap close complex copy delete imag len
      make new panic print println real recover
    ] # :nodoc:
    
    IDENT_KIND = WordList.new(:ident).
      add(KEYWORDS, :keyword).
      add(PREDEFINED_TYPES, :predefined_type).
      add(PREDEFINED_CONSTANTS, :predefined_constant).
      add(PREDEFINED_FUNCTIONS, :predefined)  # :nodoc:
    
    ESCAPE = / [rbfntv\n\\'"] | x[a-fA-F0-9]{1,2} | [0-7]{1,3} /x  # :nodoc:
    UNICODE_ESCAPE = / u[a-fA-F0-9]{4} | U[a-fA-F0-9]{8} /x  # :nodoc:
    
    protected
    
    def scan_tokens encoder, options
      
      state = :initial
      label_expected = true
      case_expected = false
      label_expected_before_preproc_line = nil
      in_preproc_line = false
      
      until eos?
        
        case state
        
        when :initial
          
          if match = scan(/ \s+ | \\\n /x)
            if in_preproc_line && match != "\\\n" && match.index(?\n)
              in_preproc_line = false
              case_expected = false
              label_expected = label_expected_before_preproc_line
            end
            encoder.text_token match, :space
          
          elsif match = scan(%r! // [^\n\\]* (?: \\. [^\n\\]* )* | /\* (?: .*? \*/ | .* ) !mx)
            encoder.text_token match, :comment
          
          elsif match = scan(/ <?- (?![\d.]) | [+*=<>?:;,!&^|()\[\]{}~%]+ | \/=? | \.(?!\d) /x)
            if case_expected
              label_expected = true if match == ':'
              case_expected = false
            end
            encoder.text_token match, :operator
          
          elsif match = scan(/ [A-Za-z_][A-Za-z_0-9]* /x)
            kind = IDENT_KIND[match]
            if kind == :ident && label_expected && !in_preproc_line && scan(/:(?!:)/)
              kind = :label
              label_expected = false
              match << matched
            else
              label_expected = false
              if kind == :keyword
                case match
                when 'case', 'default'
                  case_expected = true
                end
              end
            end
            encoder.text_token match, kind
          
          elsif match = scan(/L?"/)
            encoder.begin_group :string
            if match[0] == ?L
              encoder.text_token 'L', :modifier
              match = '"'
            end
            encoder.text_token match, :delimiter
            state = :string
          
          elsif match = scan(/ ` ([^`]+)? (`)? /x)
            encoder.begin_group :shell
            encoder.text_token '`', :delimiter
            encoder.text_token self[1], :content if self[1]
            encoder.text_token self[2], :delimiter if self[2]
            encoder.end_group :shell
          
          elsif match = scan(/ \# \s* if \s* 0 /x)
            match << scan_until(/ ^\# (?:elif|else|endif) .*? $ | \z /xm) unless eos?
            encoder.text_token match, :comment
          
          elsif match = scan(/#[ \t]*(\w*)/)
            encoder.text_token match, :preprocessor
            in_preproc_line = true
            label_expected_before_preproc_line = label_expected
            state = :include_expected if self[1] == 'include'
          
          elsif match = scan(/ L?' (?: [^\'\n\\] | \\ (?: #{ESCAPE} | #{UNICODE_ESCAPE} ) )? '? /ox)
            label_expected = false
            encoder.text_token match, :char
          
          elsif match = scan(/\$/)
            encoder.text_token match, :ident
          
          elsif match = scan(/-?\d*(\.\d*)?([eE][+-]?\d+)?i/)
            label_expected = false
            encoder.text_token match, :imaginary
          
          elsif match = scan(/-?0[xX][0-9A-Fa-f]+/)
            label_expected = false
            encoder.text_token match, :hex
          
          elsif match = scan(/-?(?:0[0-7]+)(?![89.eEfF])/)
            label_expected = false
            encoder.text_token match, :octal
          
          elsif match = scan(/-?(?:\d*\.\d+|\d+\.)(?:[eE][+-]?\d+)?|\d+[eE][+-]?\d+/)
            label_expected = false
            encoder.text_token match, :float
          
          elsif match = scan(/-?(?:\d+)(?![.eEfF])L?L?/)
            label_expected = false
            encoder.text_token match, :integer
          
          else
            encoder.text_token getch, :error
          
          end
        
        when :string
          if match = scan(/[^\\\n"]+/)
            encoder.text_token match, :content
          elsif match = scan(/"/)
            encoder.text_token match, :delimiter
            encoder.end_group :string
            state = :initial
            label_expected = false
          elsif match = scan(/ \\ (?: #{ESCAPE} | #{UNICODE_ESCAPE} ) /mox)
            encoder.text_token match, :char
          elsif match = scan(/ \\ /x)
            encoder.text_token match, :error
          elsif match = scan(/$/)
            encoder.end_group :string
            state = :initial
            label_expected = false
          else
            raise_inspect "else case \" reached; %p not handled." % peek(1), encoder
          end
        
        when :include_expected
          if match = scan(/<[^>\n]+>?|"[^"\n\\]*(?:\\.[^"\n\\]*)*"?/)
            encoder.text_token match, :include
            state = :initial
          
          elsif match = scan(/\s+/)
            encoder.text_token match, :space
            state = :initial if match.index ?\n
          
          else
            state = :initial
          
          end
        
        else
          raise_inspect 'Unknown state', encoder
        
        end
        
      end
      
      if state == :string
        encoder.end_group :string
      end
      
      encoder
    end
    
  end
  
end
end
