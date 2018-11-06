module CodeRay
module Scanners
  
  # Scanner for JSON (JavaScript Object Notation).
  class JSON < Scanner
    
    register_for :json
    file_extension 'json'
    
    KINDS_NOT_LOC = [
      :float, :char, :content, :delimiter,
      :error, :integer, :operator, :value,
    ]  # :nodoc:
    
    ESCAPE = / [bfnrt\\"\/] /x  # :nodoc:
    UNICODE_ESCAPE = / u[a-fA-F0-9]{4} /x  # :nodoc:
    KEY = / (?> (?: [^\\"]+ | \\. )* ) " \s* : /x
    
  protected
    
    def setup
      @state = :initial
    end
    
    # See http://json.org/ for a definition of the JSON lexic/grammar.
    def scan_tokens encoder, options
      state = options[:state] || @state
      
      if [:string, :key].include? state
        encoder.begin_group state
      end
      
      until eos?
        
        case state
        
        when :initial
          if match = scan(/ \s+ /x)
            encoder.text_token match, :space
          elsif match = scan(/"/)
            state = check(/#{KEY}/o) ? :key : :string
            encoder.begin_group state
            encoder.text_token match, :delimiter
          elsif match = scan(/ [:,\[{\]}] /x)
            encoder.text_token match, :operator
          elsif match = scan(/ true | false | null /x)
            encoder.text_token match, :value
          elsif match = scan(/ -? (?: 0 | [1-9]\d* ) /x)
            if scan(/ \.\d+ (?:[eE][-+]?\d+)? | [eE][-+]? \d+ /x)
              match << matched
              encoder.text_token match, :float
            else
              encoder.text_token match, :integer
            end
          else
            encoder.text_token getch, :error
          end
          
        when :string, :key
          if match = scan(/[^\\"]+/)
            encoder.text_token match, :content
          elsif match = scan(/"/)
            encoder.text_token match, :delimiter
            encoder.end_group state
            state = :initial
          elsif match = scan(/ \\ (?: #{ESCAPE} | #{UNICODE_ESCAPE} ) /mox)
            encoder.text_token match, :char
          elsif match = scan(/\\./m)
            encoder.text_token match, :content
          elsif match = scan(/ \\ | $ /x)
            encoder.end_group state
            encoder.text_token match, :error unless match.empty?
            state = :initial
          else
            raise_inspect "else case \" reached; %p not handled." % peek(1), encoder
          end
          
        else
          raise_inspect 'Unknown state: %p' % [state], encoder
          
        end
      end
      
      if options[:keep_state]
        @state = state
      end
      
      if [:string, :key].include? state
        encoder.end_group state
      end
      
      encoder
    end
    
  end
  
end
end
