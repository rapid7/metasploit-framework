module CodeRay
module Encoders
  
  load :html
  
  # Wraps HTML output into a SPAN element, using inline styles by default.
  # 
  # See Encoders::HTML for available options.
  class Span < HTML
    
    FILE_EXTENSION = 'span.html'
    
    register_for :span
    
    DEFAULT_OPTIONS = HTML::DEFAULT_OPTIONS.merge \
      :css          => :style,
      :wrap         => :span,
      :line_numbers => false
    
  end
  
end
end
