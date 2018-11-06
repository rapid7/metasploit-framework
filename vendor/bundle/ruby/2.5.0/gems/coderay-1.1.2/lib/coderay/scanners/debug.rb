require 'set'

module CodeRay
module Scanners
  
  # = Debug Scanner
  # 
  # Interprets the output of the Encoders::Debug encoder (basically the inverse function).
  class Debug < Scanner
    
    register_for :debug
    title 'CodeRay Token Dump Import'
    
  protected
    
    def setup
      super
      @known_token_kinds = TokenKinds.keys.map(&:to_s).to_set
    end
    
    def scan_tokens encoder, options
      
      opened_tokens = []
      
      until eos?
        
        if match = scan(/\s+/)
          encoder.text_token match, :space
          
        elsif match = scan(/ (\w+) \( ( [^\)\\]* ( \\. [^\)\\]* )* ) \)? /x)
          if @known_token_kinds.include? self[1]
            encoder.text_token self[2].gsub(/\\(.)/m, '\1'), self[1].to_sym
          else
            encoder.text_token matched, :unknown
          end
          
        elsif match = scan(/ (\w+) ([<\[]) /x)
          if @known_token_kinds.include? self[1]
            kind = self[1].to_sym
          else
            kind = :unknown
          end
          
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
