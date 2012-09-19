# encoding: utf-8
# 
# resent-msg-id   =       "Resent-Message-ID:" msg-id CRLF
require 'mail/fields/common/common_message_id'

module Mail
  class ResentMessageIdField < StructuredField
    
    include CommonMessageId
    
    FIELD_NAME = 'resent-message-id'
    CAPITALIZED_FIELD = 'Resent-Message-ID'
    
    def initialize(value = nil, charset = 'utf-8')
      self.charset = charset
      super(CAPITALIZED_FIELD, strip_field(FIELD_NAME, value), charset)
      self.parse
      self
    end
    
    def name
      'Resent-Message-ID'
    end
    
    def encoded
      do_encode(CAPITALIZED_FIELD)
    end
    
    def decoded
      do_decode
    end
    
  end
end
