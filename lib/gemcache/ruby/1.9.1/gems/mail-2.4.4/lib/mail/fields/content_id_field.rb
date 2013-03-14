# encoding: utf-8
# 
# 
# 
module Mail
  class ContentIdField < StructuredField
    
    FIELD_NAME = 'content-id'
    CAPITALIZED_FIELD = "Content-ID"
    
    def initialize(value = nil, charset = 'utf-8')
      self.charset = charset
      @uniq = 1
      if value.blank?
        value = generate_content_id
      else
        value = strip_field(FIELD_NAME, value)
      end
      super(CAPITALIZED_FIELD, strip_field(FIELD_NAME, value), charset)
      self.parse
      self
    end
    
    def parse(val = value)
      unless val.blank?
        @element = Mail::MessageIdsElement.new(val)
      end
    end
    
    def element
      @element ||= Mail::MessageIdsElement.new(value)
    end
    
    def name
      'Content-ID'
    end
    
    def content_id
      element.message_id
    end
    
    def to_s
      "<#{content_id}>"
    end
    
    # TODO: Fix this up
    def encoded
      "#{CAPITALIZED_FIELD}: #{to_s}\r\n"
    end
    
    def decoded
      "#{to_s}"
    end
    
    private
    
    def generate_content_id
      fqdn = ::Socket.gethostname
      "<#{Mail.random_tag}@#{fqdn}.mail>"
    end
    
  end
end
