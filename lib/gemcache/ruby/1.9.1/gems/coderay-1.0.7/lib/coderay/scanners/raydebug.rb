module CodeRay
module Scanners

  # = Debug Scanner
  # 
  # Parses the output of the Encoders::Debug encoder.
  class Raydebug < Scanner

    register_for :raydebug
    file_extension 'raydebug'
    title 'CodeRay Token Dump'
    
  protected
    
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
          encoder.text_token match, kind.to_sym
          encoder.text_token match, :operator if match = scan(/\)/)
          
        elsif match = scan(/ (\w+) ([<\[]) /x)
          kind = self[1]
          case self[2]
          when '<'
            encoder.text_token kind, :class
          when '['
            encoder.text_token kind, :class
          else
            raise 'CodeRay bug: This case should not be reached.'
          end
          kind = kind.to_sym
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
