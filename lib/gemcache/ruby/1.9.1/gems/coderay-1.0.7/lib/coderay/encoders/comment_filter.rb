module CodeRay
module Encoders
  
  load :token_kind_filter
  
  # A simple Filter that removes all tokens of the :comment kind.
  # 
  # Alias: +remove_comments+
  # 
  # Usage:
  #  CodeRay.scan('print # foo', :ruby).comment_filter.text
  #  #-> "print "
  # 
  # See also: TokenKindFilter, LinesOfCode
  class CommentFilter < TokenKindFilter
    
    register_for :comment_filter
    
    DEFAULT_OPTIONS = superclass::DEFAULT_OPTIONS.merge \
      :exclude => [:comment, :docstring]
    
  end
  
end
end
