module CodeRay
module Scanners
  
  # Scanner for the Delphi language (Object Pascal).
  # 
  # Alias: +pascal+
  class Delphi < Scanner
    
    register_for :delphi
    file_extension 'pas'
    
    KEYWORDS = [
      'and', 'array', 'as', 'at', 'asm', 'at', 'begin', 'case', 'class',
      'const', 'constructor', 'destructor', 'dispinterface', 'div', 'do',
      'downto', 'else', 'end', 'except', 'exports', 'file', 'finalization',
      'finally', 'for', 'function', 'goto', 'if', 'implementation', 'in',
      'inherited', 'initialization', 'inline', 'interface', 'is', 'label',
      'library', 'mod', 'nil', 'not', 'object', 'of', 'or', 'out', 'packed',
      'procedure', 'program', 'property', 'raise', 'record', 'repeat',
      'resourcestring', 'set', 'shl', 'shr', 'string', 'then', 'threadvar',
      'to', 'try', 'type', 'unit', 'until', 'uses', 'var', 'while', 'with',
      'xor', 'on',
    ]  # :nodoc:
    
    DIRECTIVES = [
      'absolute', 'abstract', 'assembler', 'at', 'automated', 'cdecl',
      'contains', 'deprecated', 'dispid', 'dynamic', 'export',
      'external', 'far', 'forward', 'implements', 'local', 
      'near', 'nodefault', 'on', 'overload', 'override',
      'package', 'pascal', 'platform', 'private', 'protected', 'public',
      'published', 'read', 'readonly', 'register', 'reintroduce',
      'requires', 'resident', 'safecall', 'stdcall', 'stored', 'varargs',
      'virtual', 'write', 'writeonly',
    ]  # :nodoc:
    
    IDENT_KIND = WordList::CaseIgnoring.new(:ident).
      add(KEYWORDS, :keyword).
      add(DIRECTIVES, :directive)  # :nodoc:
    
    NAME_FOLLOWS = WordList::CaseIgnoring.new(false).
      add(%w(procedure function .))  # :nodoc:
    
  protected
    
    def scan_tokens encoder, options
      
      state = :initial
      last_token = ''
      
      until eos?
        
        if state == :initial
          
          if match = scan(/ \s+ /x)
            encoder.text_token match, :space
            next
            
          elsif match = scan(%r! \{ \$ [^}]* \}? | \(\* \$ (?: .*? \*\) | .* ) !mx)
            encoder.text_token match, :preprocessor
            next
            
          elsif match = scan(%r! // [^\n]* | \{ [^}]* \}? | \(\* (?: .*? \*\) | .* ) !mx)
            encoder.text_token match, :comment
            next
            
          elsif match = scan(/ <[>=]? | >=? | :=? | [-+=*\/;,@\^|\(\)\[\]] | \.\. /x)
            encoder.text_token match, :operator
          
          elsif match = scan(/\./)
            encoder.text_token match, :operator
            next if last_token == 'end'
            
          elsif match = scan(/ [A-Za-z_][A-Za-z_0-9]* /x)
            encoder.text_token match, NAME_FOLLOWS[last_token] ? :ident : IDENT_KIND[match]
            
          elsif match = skip(/ ' ( [^\n']|'' ) (?:'|$) /x)
            encoder.begin_group :char
            encoder.text_token "'", :delimiter
            encoder.text_token self[1], :content
            encoder.text_token "'", :delimiter
            encoder.end_group :char
            next
            
          elsif match = scan(/ ' /x)
            encoder.begin_group :string
            encoder.text_token match, :delimiter
            state = :string
            
          elsif match = scan(/ \# (?: \d+ | \$[0-9A-Fa-f]+ ) /x)
            encoder.text_token match, :char
            
          elsif match = scan(/ \$ [0-9A-Fa-f]+ /x)
            encoder.text_token match, :hex
            
          elsif match = scan(/ (?: \d+ ) (?![eE]|\.[^.]) /x)
            encoder.text_token match, :integer
            
          elsif match = scan(/ \d+ (?: \.\d+ (?: [eE][+-]? \d+ )? | [eE][+-]? \d+ ) /x)
            encoder.text_token match, :float
            
          else
            encoder.text_token getch, :error
            next
            
          end
          
        elsif state == :string
          if match = scan(/[^\n']+/)
            encoder.text_token match, :content
          elsif match = scan(/''/)
            encoder.text_token match, :char
          elsif match = scan(/'/)
            encoder.text_token match, :delimiter
            encoder.end_group :string
            state = :initial
            next
          elsif match = scan(/\n/)
            encoder.end_group :string
            encoder.text_token match, :space
            state = :initial
          else
            raise "else case \' reached; %p not handled." % peek(1), encoder
          end
          
        else
          raise 'else-case reached', encoder
          
        end
        
        last_token = match
        
      end
      
      if state == :string
        encoder.end_group state
      end
      
      encoder
    end

  end

end
end
