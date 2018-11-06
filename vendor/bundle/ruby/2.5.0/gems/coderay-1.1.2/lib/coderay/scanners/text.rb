module CodeRay
  module Scanners
    
    # Scanner for plain text.
    # 
    # Yields just one token of the kind :plain.
    # 
    # Alias: +plaintext+, +plain+
    class Text < Scanner
      
      register_for :text
      title 'Plain text'
      
      KINDS_NOT_LOC = [:plain]  # :nodoc:
      
    protected
      
      def scan_tokens encoder, options
        encoder.text_token string, :plain
        encoder
      end
      
    end
    
  end
end
