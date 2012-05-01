module CodeRay
module Encoders
  
  load :html
  
  # Wraps the output into a HTML page, using CSS classes and
  # line numbers in the table format by default.
  # 
  # See Encoders::HTML for available options.
  class Page < HTML
    
    FILE_EXTENSION = 'html'
    
    register_for :page
    
    DEFAULT_OPTIONS = HTML::DEFAULT_OPTIONS.merge \
      :css          => :class,
      :wrap         => :page,
      :line_numbers => :table
    
  end
  
end
end
