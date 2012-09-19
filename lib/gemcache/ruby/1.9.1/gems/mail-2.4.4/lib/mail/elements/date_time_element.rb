# encoding: utf-8
module Mail
  class DateTimeElement # :nodoc:
    
    include Mail::Utilities
    
    def initialize( string )
      parser = Mail::DateTimeParser.new
      if tree = parser.parse(string)
        @date_string = tree.date.text_value
        @time_string = tree.time.text_value
      else
        raise Mail::Field::ParseError.new(DateTimeElement, string, parser.failure_reason)
      end
    end
    
    def date_string
      @date_string
    end
    
    def time_string
      @time_string
    end
    
  end
end
