# encoding: utf-8
# 
# subject         =       "Subject:" unstructured CRLF
module Mail
  class SubjectField < UnstructuredField
    
    FIELD_NAME = 'subject'
    CAPITALIZED_FIELD = "Subject"
    
    def initialize(value = nil, charset = 'utf-8')
      self.charset = charset
      super(CAPITALIZED_FIELD, strip_field(FIELD_NAME, value), charset)
    end
    
  end
end
