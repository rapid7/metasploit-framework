module CodeRay

  # This module holds the Style class and its subclasses.
  # 
  # See Plugin.
  module Styles
    extend PluginHost
    plugin_path File.dirname(__FILE__), 'styles'
    
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
