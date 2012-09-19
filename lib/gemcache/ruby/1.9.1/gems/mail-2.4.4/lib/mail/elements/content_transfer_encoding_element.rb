# encoding: utf-8
module Mail
  class ContentTransferEncodingElement
    
    include Mail::Utilities
    
    def initialize( string )
      parser = Mail::ContentTransferEncodingParser.new
      case
      when string.blank?
        @encoding = ''
      when tree = parser.parse(string.to_s.downcase)
        @encoding = tree.encoding.text_value
      else
        raise Mail::Field::ParseError.new(ContentTransferEncodingElement, string, parser.failure_reason)
      end
    end
    
    def encoding
      @encoding
    end
    
  end
end
