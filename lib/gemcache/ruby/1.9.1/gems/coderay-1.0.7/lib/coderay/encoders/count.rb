module CodeRay
module Encoders
  
  # Returns the number of tokens.
  # 
  # Text and block tokens are counted.
  class Count < Encoder
    
    register_for :count
    
  protected
    
    def setup options
      super
      
      @count = 0
    end
    
    def finish options
      output @count
    end
    
  public
    
    def text_token text, kind
      @count += 1
    end
    
    def begin_group kind
      @count += 1
    end
    alias end_group begin_group
    alias begin_line begin_group
    alias end_line begin_group
    
  end
  
end
end
