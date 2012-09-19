# encoding: utf-8
module Mail
  class MessageIdsElement
    
    include Mail::Utilities
    
    def initialize(string)
      parser = Mail::MessageIdsParser.new
      if tree = parser.parse(string)
        @message_ids = tree.message_ids.map { |msg_id| clean_msg_id(msg_id.text_value) }
      else
        raise Mail::Field::ParseError.new(MessageIdsElement, string, parser.failure_reason)
      end
    end
    
    def message_ids
      @message_ids
    end
    
    def message_id
      @message_ids.first
    end
    
    def clean_msg_id( val )
      val =~ /.*<(.*)>.*/ ; $1
    end

  end
end
