module CodeRay
  
  # This module holds the Encoder class and its subclasses.
  # For example, the HTML encoder is named CodeRay::Encoders::HTML
  # can be found in coderay/encoders/html.
  #
  # Encoders also provides methods and constants for the register
  # mechanism and the [] method that returns the Encoder class
  # belonging to the given format.
  module Encoders
    
    extend PluginHost
    plugin_path File.dirname(__FILE__), 'encoders'
    
    autoload :Encoder, CodeRay.coderay_path('encoders', 'encoder')
    
  end
end
