module CodeRay
module Encoders
  
  load :html
  
  # Wraps HTML output into a DIV element, using inline styles by default.
  # 
  # See Encoders::HTML for available options.
  class Div < HTML
    
    FILE_EXTENSION = 'div.html'
    
    register_for :div
    
    DEFAULT_OPTIONS = HTML::DEFAULT_OPTIONS.merge \
      :css          => :style,
      :wrap         => :div,
      :line_numbers => false
    
  end
  
end
end
