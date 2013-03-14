module CodeRay
module Encoders
  
  # A Filter encoder has another Tokens instance as output.
  # It can be subclass to select, remove, or modify tokens in the stream.
  # 
  # Subclasses of Filter are called "Filters" and can be chained.
  # 
  # == Options
  # 
  # === :tokens
  # 
  # The Tokens object which will receive the output.
  # 
  # Default: Tokens.new
  # 
  # See also: TokenKindFilter
  class Filter < Encoder
    
    register_for :filter
    
  protected
    def setup options
      super
      
      @tokens = options[:tokens] || Tokens.new
    end
    
    def finish options
      output @tokens
    end
    
  public
    
    def text_token text, kind  # :nodoc:
      @tokens.text_token text, kind
    end
    
    def begin_group kind  # :nodoc:
      @tokens.begin_group kind
    end
    
    def begin_line kind  # :nodoc:
      @tokens.begin_line kind
    end
    
    def end_group kind  # :nodoc:
      @tokens.end_group kind
    end
    
    def end_line kind  # :nodoc:
      @tokens.end_line kind
    end
    
  end
  
end
end
