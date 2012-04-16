module CodeRay
module Scanners
  
  # = Debug Scanner
  # 
  # Interprets the output of the Encoders::Debug encoder.
  class Debug < Scanner
    
    register_for :debug
    title 'CodeRay Token Dump Import'
    
  protected
    
    def scan_tokens encoder, options
      
      opened_tokens = []
      
      until eos?
        
        if match = scan(/\s+/)
          encoder.text_token match, :space
          
        elsif match = scan(/ (\w+) \( ( [^\)\\]* ( \\. [^\)\\]* )* ) \)? /x)
          kind = self[1].to_sym
          match = self[2].gsub(/\\(.)/m, '\1')
          unless TokenKinds.has_key? kind
            kind = :error
            match = matched
          end
          encoder.text_token match, kind
          
        elsif match = scan(/ (\w+) ([<\[]) /x)
          kind = self[1].to_sym
          opened_tokens << kind
          case self[2]
          when '<'
            encoder.begin_group kind
          when '['
            encoder.begin_line kind
          else
            raise 'CodeRay bug: This case should not be reached.'
          end
          
        elsif !opened_tokens.empty? && match = scan(/ > /x)
          encoder.end_group opened_tokens.pop
          
        elsif !opened_tokens.empty? && match = scan(/ \] /x)
          encoder.end_line opened_tokens.pop
          
        else
          encoder.text_token getch, :space
          
        end
        
      end
      
      encoder.end_group opened_tokens.pop until opened_tokens.empty?
      
      encoder
    end
    
  end
  
end
end
