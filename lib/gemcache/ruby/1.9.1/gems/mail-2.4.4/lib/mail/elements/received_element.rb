# encoding: utf-8
module Mail
  class ReceivedElement
    
    include Mail::Utilities
    
    def initialize( string )
      parser = Mail::ReceivedParser.new
      if tree = parser.parse(string)
        @date_time = ::DateTime.parse("#{tree.date_time.date.text_value} #{tree.date_time.time.text_value}")
        @info = tree.name_val_list.text_value
      else
        raise Mail::Field::ParseError.new(ReceivedElement, string, parser.failure_reason)
      end
    end
    
    def date_time
      @date_time
    end
    
    def info
      @info
    end
    
    def to_s(*args)
      "#{@info}; #{@date_time.to_s(*args)}"
    end
    
  end
end
