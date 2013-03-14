module CodeRay
module Scanners

  # Scanner for C++.
  # 
  # Aliases: +cplusplus+, c++
  class CPlusPlus < Scanner

    register_for :cpp
    file_extension 'cpp'
    title 'C++'
    
    #-- http://www.cppreference.com/wiki/keywords/start
    KEYWORDS = [
      'and', 'and_eq', 'asm', 'bitand', 'bitor', 'break',
      'case', 'catch', 'class', 'compl', 'const_cast',
      'continue', 'default', 'delete', 'do', 'dynamic_cast', 'else',
      'enum', 'export', 'for', 'goto', 'if', 'namespace', 'new',
      'not', 'not_eq', 'or', 'or_eq', 'reinterpret_cast', 'return',
      'sizeof', 'static_cast', 'struct', 'switch', 'template',
      'throw', 'try', 'typedef', 'typeid', 'typename', 'union',
      'while', 'xor', 'xor_eq',
    ]  # :nodoc:
    
    PREDEFINED_TYPES = [
      'bool', 'char', 'double', 'float', 'int', 'long',
      'short', 'signed', 'unsigned', 'wchar_t', 'string',
    ]  # :nodoc:
    PREDEFINED_CONSTANTS = [
      'false', 'true',
      'EOF', 'NULL',
    ]  # :nodoc:
    PREDEFINED_VARIABLES = [
      'this',
    ]  # :nodoc:
    DIRECTIVES = [
      'auto', 'const', 'explicit', 'extern', 'friend', 'inline', 'mutable', 'operator',
      'private', 'protected', 'public', 'register', 'static', 'using', 'virtual', 'void',
      'volatile',
    ]  # :nodoc:
    
    IDENT_KIND = WordList.new(:ident).
      add(KEYWORDS, :keyword).
      add(PREDEFINED_TYPES, :predefined_type).
      add(PREDEFINED_VARIABLES, :local_variable).
      add(DIRECTIVES, :directive).
      add(PREDEFINED_CONSTANTS, :predefined_constant)  # :nodoc:

    ESCAPE = / [rbfntv\n\\'"] | x[a-fA-F0-9]{1,2} | [0-7]{1,3} /x  # :nodoc:
    UNICODE_ESCAPE =  / u[a-fA-F0-9]{4} | U[a-fA-F0-9]{8} /x  # :nodoc:
    
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
              label_expected = label_expected_before_preproc_line
            end
            encoder.text_token match, :space

          elsif match = scan(%r! // [^\n\\]* (?: \\. [^\n\\]* )* | /\* (?: .*? \*/ | .* ) !mx)
            encoder.text_token match, :comment

          elsif match = scan(/ \# \s* if \s* 0 /x)
            match << scan_until(/ ^\# (?:elif|else|endif) .*? $ | \z /xm) unless eos?
            encoder.text_token match, :comment

          elsif match = scan(/ [-+*=<>?:;,!&^|()\[\]{}~%]+ | \/=? | \.(?!\d) /x)
            label_expected = match =~ /[;\{\}]/
            if case_expected
              label_expected = true if match == ':'
              case_expected = false
            end
            encoder.text_token match, :operator

          elsif match = scan(/ [A-Za-z_][A-Za-z_0-9]* /x)
            kind = IDENT_KIND[match]
            if kind == :ident && label_expected && !in_preproc_line && scan(/:(?!:)/)
              kind = :label
              match << matched
            else
              label_expected = false
              if kind == :keyword
                case match
                when 'class'
                  state = :class_name_expected
                when 'case', 'default'
                  case_expected = true
                end
              end
            end
            encoder.text_token match, kind

          elsif match = scan(/\$/)
            encoder.text_token match, :ident
          
          elsif match = scan(/L?"/)
            encoder.begin_group :string
            if match[0] == ?L
              encoder.text_token match, 'L', :modifier
              match = '"'
            end
            state = :string
            encoder.text_token match, :delimiter

          elsif match = scan(/#[ \t]*(\w*)/)
            encoder.text_token match, :preprocessor
            in_preproc_line = true
            label_expected_before_preproc_line = label_expected
            state = :include_expected if self[1] == 'include'

          elsif match = scan(/ L?' (?: [^\'\n\\] | \\ #{ESCAPE} )? '? /ox)
            label_expected = false
            encoder.text_token match, :char

          elsif match = scan(/0[xX][0-9A-Fa-f]+/)
            label_expected = false
            encoder.text_token match, :hex

          elsif match = scan(/(?:0[0-7]+)(?![89.eEfF])/)
            label_expected = false
            encoder.text_token match, :octal

          elsif match = scan(/(?:\d+)(?![.eEfF])L?L?/)
            label_expected = false
            encoder.text_token match, :integer

          elsif match = scan(/\d[fF]?|\d*\.\d+(?:[eE][+-]?\d+)?[fF]?|\d+[eE][+-]?\d+[fF]?/)
            label_expected = false
            encoder.text_token match, :float

          else
            encoder.text_token getch, :error

          end

        when :string
          if match = scan(/[^\\"]+/)
            encoder.text_token match, :content
          elsif match = scan(/"/)
            encoder.text_token match, :delimiter
            encoder.end_group :string
            state = :initial
            label_expected = false
          elsif match = scan(/ \\ (?: #{ESCAPE} | #{UNICODE_ESCAPE} ) /mox)
            encoder.text_token match, :char
          elsif match = scan(/ \\ | $ /x)
            encoder.end_group :string
            encoder.text_token match, :error
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
        
        when :class_name_expected
          if match = scan(/ [A-Za-z_][A-Za-z_0-9]* /x)
            encoder.text_token match, :class
            state = :initial

          elsif match = scan(/\s+/)
            encoder.text_token match, :space

          else
            encoder.text_token getch, :error
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
