module CodeRay
module Encoders
  
  # = Null Encoder
  #
  # Does nothing and returns an empty string.
  class Null < Encoder
    
    register_for :null
    
    def text_token text, kind
      # do nothing
    end
    
  end
  
end
end
