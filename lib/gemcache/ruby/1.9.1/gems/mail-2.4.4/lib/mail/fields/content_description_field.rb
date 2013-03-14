# encoding: utf-8
# 
# 
# 
module Mail
  class ContentDescriptionField < UnstructuredField
    
    FIELD_NAME = 'content-description'
    CAPITALIZED_FIELD = 'Content-Description'
    
    def initialize(value = nil, charset = 'utf-8')
      self.charset = charset
      super(CAPITALIZED_FIELD, strip_field(FIELD_NAME, value), charset)
      self.parse
      self
    end
    
  end
end
