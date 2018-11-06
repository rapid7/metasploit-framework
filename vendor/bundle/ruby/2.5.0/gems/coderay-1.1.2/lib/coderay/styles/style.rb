module CodeRay
  
  module Styles
    
    # Base class for styles.
    # 
    # Styles are used by Encoders::HTML to colorize tokens.
    class Style
      extend Plugin
      plugin_host Styles
      
      DEFAULT_OPTIONS = { }  # :nodoc:
      
    end
    
  end
  
end
