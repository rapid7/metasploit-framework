autoload :YAML, 'yaml'

module CodeRay
module Encoders
  
  # = YAML Encoder
  #
  # Slow.
  class YAML < Encoder
    
    register_for :yaml
    
    FILE_EXTENSION = 'yaml'
    
  protected
    def setup options
      super
      
      @data = []
    end
    
    def finish options
      output ::YAML.dump(@data)
    end
    
  public
    def text_token text, kind
      @data << [text, kind]
    end
    
    def begin_group kind
      @data << [:begin_group, kind]
    end
    
    def end_group kind
      @data << [:end_group, kind]
    end
    
    def begin_line kind
      @data << [:begin_line, kind]
    end
    
    def end_line kind
      @data << [:end_line, kind]
    end
    
  end
  
end
end
