require 'set'

module CodeRay
module Scanners
  
  # = Raydebug Scanner
  # 
  # Highlights the output of the Encoders::Debug encoder.
  class Raydebug < Scanner
    
    register_for :raydebug
    file_extension 'raydebug'
    title 'CodeRay Token Dump'
    
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
          
        elsif match = scan(/ (\w+) \( ( [^\)\\]* ( \\. [^\)\\]* )* ) /x)
          kind = self[1]
          encoder.text_token kind, :class
          encoder.text_token '(', :operator
          match = self[2]
          unless match.empty?
            if @known_token_kinds.include? kind
              encoder.text_token match, kind.to_sym
            else
              encoder.text_token match, :plain
            end
          end
          encoder.text_token match, :operator if match = scan(/\)/)
          
        elsif match = scan(/ (\w+) ([<\[]) /x)
          encoder.text_token self[1], :class
          if @known_token_kinds.include? self[1]
            kind = self[1].to_sym
          else
            kind = :unknown
          end
          opened_tokens << kind
          encoder.begin_group kind
          encoder.text_token self[2], :operator
          
        elsif !opened_tokens.empty? && match = scan(/ [>\]] /x)
          encoder.text_token match, :operator
          encoder.end_group opened_tokens.pop
          
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
