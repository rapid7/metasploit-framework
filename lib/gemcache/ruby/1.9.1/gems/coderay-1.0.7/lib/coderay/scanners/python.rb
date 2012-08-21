module CodeRay
module Scanners
  
  # Scanner for Python. Supports Python 3.
  # 
  # Based on pygments' PythonLexer, see
  # http://dev.pocoo.org/projects/pygments/browser/pygments/lexers/agile.py.
  class Python < Scanner
    
    register_for :python
    file_extension 'py'
    
    KEYWORDS = [
      'and', 'as', 'assert', 'break', 'class', 'continue', 'def',
      'del', 'elif', 'else', 'except', 'finally', 'for',
      'from', 'global', 'if', 'import', 'in', 'is', 'lambda', 'not',
      'or', 'pass', 'raise', 'return', 'try', 'while', 'with', 'yield',
      'nonlocal',  # new in Python 3
    ]  # :nodoc:
    
    OLD_KEYWORDS = [
      'exec', 'print',  # gone in Python 3
    ]  # :nodoc:
    
    PREDEFINED_METHODS_AND_TYPES = %w[
      __import__ abs all any apply basestring bin bool buffer
      bytearray bytes callable chr classmethod cmp coerce compile
      complex delattr dict dir divmod enumerate eval execfile exit
      file filter float frozenset getattr globals hasattr hash hex id
      input int intern isinstance issubclass iter len list locals
      long map max min next object oct open ord pow property range
      raw_input reduce reload repr reversed round set setattr slice
      sorted staticmethod str sum super tuple type unichr unicode
      vars xrange zip
    ]  # :nodoc:
    
    PREDEFINED_EXCEPTIONS = %w[
      ArithmeticError AssertionError AttributeError
      BaseException DeprecationWarning EOFError EnvironmentError
      Exception FloatingPointError FutureWarning GeneratorExit IOError
      ImportError ImportWarning IndentationError IndexError KeyError
      KeyboardInterrupt LookupError MemoryError NameError
      NotImplemented NotImplementedError OSError OverflowError
      OverflowWarning PendingDeprecationWarning ReferenceError
      RuntimeError RuntimeWarning StandardError StopIteration
      SyntaxError SyntaxWarning SystemError SystemExit TabError
      TypeError UnboundLocalError UnicodeDecodeError
      UnicodeEncodeError UnicodeError UnicodeTranslateError
      UnicodeWarning UserWarning ValueError Warning ZeroDivisionError
    ]  # :nodoc:
    
    PREDEFINED_VARIABLES_AND_CONSTANTS = [
      'False', 'True', 'None',  # "keywords" since Python 3
      'self', 'Ellipsis', 'NotImplemented',
    ]  # :nodoc:
    
    IDENT_KIND = WordList.new(:ident).
      add(KEYWORDS, :keyword).
      add(OLD_KEYWORDS, :old_keyword).
      add(PREDEFINED_METHODS_AND_TYPES, :predefined).
      add(PREDEFINED_VARIABLES_AND_CONSTANTS, :predefined_constant).
      add(PREDEFINED_EXCEPTIONS, :exception)  # :nodoc:
    
    NAME = / [[:alpha:]_] \w* /x  # :nodoc:
    ESCAPE = / [abfnrtv\n\\'"] | x[a-fA-F0-9]{1,2} | [0-7]{1,3} /x  # :nodoc:
    UNICODE_ESCAPE =  / u[a-fA-F0-9]{4} | U[a-fA-F0-9]{8} | N\{[-\w ]+\} /x  # :nodoc:
    
    OPERATOR = /
      \.\.\. |          # ellipsis
      \.(?!\d) |        # dot but not decimal point
      [,;:()\[\]{}] |   # simple delimiters
      \/\/=? | \*\*=? | # special math
      [-+*\/%&|^]=? |   # ordinary math and binary logic
      [~`] |            # binary complement and inspection
      <<=? | >>=? | [<>=]=? | !=  # comparison and assignment
    /x  # :nodoc:
    
    STRING_DELIMITER_REGEXP = Hash.new { |h, delimiter|
      h[delimiter] = Regexp.union delimiter  # :nodoc:
    }
    
    STRING_CONTENT_REGEXP = Hash.new { |h, delimiter|
      h[delimiter] = / [^\\\n]+? (?= \\ | $ | #{Regexp.escape(delimiter)} ) /x  # :nodoc:
    }
    
    DEF_NEW_STATE = WordList.new(:initial).
      add(%w(def), :def_expected).
      add(%w(import from), :include_expected).
      add(%w(class), :class_expected)  # :nodoc:
    
    DESCRIPTOR = /
      #{NAME}
      (?: \. #{NAME} )*
      | \*
    /x  # :nodoc:
    
    DOCSTRING_COMING = /
      [ \t]* u?r? ("""|''')
    /x  # :nodoc:
    
  protected
    
    def scan_tokens encoder, options
      
      state = :initial
      string_delimiter = nil
      string_raw = false
      string_type = nil
      docstring_coming = match?(/#{DOCSTRING_COMING}/o)
      last_token_dot = false
      unicode = string.respond_to?(:encoding) && string.encoding.name == 'UTF-8'
      from_import_state = []
      
      until eos?
        
        if state == :string
          if match = scan(STRING_DELIMITER_REGEXP[string_delimiter])
            encoder.text_token match, :delimiter
            encoder.end_group string_type
            string_type = nil
            state = :initial
            next
          elsif string_delimiter.size == 3 && match = scan(/\n/)
            encoder.text_token match, :content
          elsif match = scan(STRING_CONTENT_REGEXP[string_delimiter])
            encoder.text_token match, :content
          elsif !string_raw && match = scan(/ \\ #{ESCAPE} /ox)
            encoder.text_token match, :char
          elsif match = scan(/ \\ #{UNICODE_ESCAPE} /ox)
            encoder.text_token match, :char
          elsif match = scan(/ \\ . /x)
            encoder.text_token match, :content
          elsif match = scan(/ \\ | $ /x)
            encoder.end_group string_type
            string_type = nil
            encoder.text_token match, :error
            state = :initial
          else
            raise_inspect "else case \" reached; %p not handled." % peek(1), encoder, state
          end
        
        elsif match = scan(/ [ \t]+ | \\?\n /x)
          encoder.text_token match, :space
          if match == "\n"
            state = :initial if state == :include_expected
            docstring_coming = true if match?(/#{DOCSTRING_COMING}/o)
          end
          next
        
        elsif match = scan(/ \# [^\n]* /mx)
          encoder.text_token match, :comment
          next
        
        elsif state == :initial
          
          if match = scan(/#{OPERATOR}/o)
            encoder.text_token match, :operator
          
          elsif match = scan(/(u?r?|b)?("""|"|'''|')/i)
            string_delimiter = self[2]
            string_type = docstring_coming ? :docstring : :string
            docstring_coming = false if docstring_coming
            encoder.begin_group string_type
            string_raw = false
            modifiers = self[1]
            unless modifiers.empty?
              string_raw = !!modifiers.index(?r)
              encoder.text_token modifiers, :modifier
              match = string_delimiter
            end
            state = :string
            encoder.text_token match, :delimiter
          
          # TODO: backticks
          
          elsif match = scan(unicode ? /#{NAME}/uo : /#{NAME}/o)
            kind = IDENT_KIND[match]
            # TODO: keyword arguments
            kind = :ident if last_token_dot
            if kind == :old_keyword
              kind = check(/\(/) ? :ident : :keyword
            elsif kind == :predefined && check(/ *=/)
              kind = :ident
            elsif kind == :keyword
              state = DEF_NEW_STATE[match]
              from_import_state << match.to_sym if state == :include_expected
            end
            encoder.text_token match, kind
          
          elsif match = scan(/@[a-zA-Z0-9_.]+[lL]?/)
            encoder.text_token match, :decorator
          
          elsif match = scan(/0[xX][0-9A-Fa-f]+[lL]?/)
            encoder.text_token match, :hex
          
          elsif match = scan(/0[bB][01]+[lL]?/)
            encoder.text_token match, :binary
          
          elsif match = scan(/(?:\d*\.\d+|\d+\.\d*)(?:[eE][+-]?\d+)?|\d+[eE][+-]?\d+/)
            if scan(/[jJ]/)
              match << matched
              encoder.text_token match, :imaginary
            else
              encoder.text_token match, :float
            end
          
          elsif match = scan(/0[oO][0-7]+|0[0-7]+(?![89.eE])[lL]?/)
            encoder.text_token match, :octal
          
          elsif match = scan(/\d+([lL])?/)
            if self[1] == nil && scan(/[jJ]/)
              match << matched
              encoder.text_token match, :imaginary
            else
              encoder.text_token match, :integer
            end
          
          else
            encoder.text_token getch, :error
          
          end
            
        elsif state == :def_expected
          state = :initial
          if match = scan(unicode ? /#{NAME}/uo : /#{NAME}/o)
            encoder.text_token match, :method
          else
            next
          end
        
        elsif state == :class_expected
          state = :initial
          if match = scan(unicode ? /#{NAME}/uo : /#{NAME}/o)
            encoder.text_token match, :class
          else
            next
          end
          
        elsif state == :include_expected
          if match = scan(unicode ? /#{DESCRIPTOR}/uo : /#{DESCRIPTOR}/o)
            if match == 'as'
              encoder.text_token match, :keyword
              from_import_state << :as
            elsif from_import_state.first == :from && match == 'import'
              encoder.text_token match, :keyword
              from_import_state << :import
            elsif from_import_state.last == :as
              # encoder.text_token match, match[0,1][unicode ? /[[:upper:]]/u : /[[:upper:]]/] ? :class : :method
              encoder.text_token match, :ident
              from_import_state.pop
            elsif IDENT_KIND[match] == :keyword
              unscan
              match = nil
              state = :initial
              next
            else
              encoder.text_token match, :include
            end
          elsif match = scan(/,/)
            from_import_state.pop if from_import_state.last == :as
            encoder.text_token match, :operator
          else
            from_import_state = []
            state = :initial
            next
          end
          
        else
          raise_inspect 'Unknown state', encoder, state
          
        end
        
        last_token_dot = match == '.'
        
      end
      
      if state == :string
        encoder.end_group string_type
      end
      
      encoder
    end
    
  end
  
end
end
