module IceCube

  class StringBuilder

    attr_writer :base

    def initialize
      @types = {}
    end

    def piece(type, prefix = nil, suffix = nil)
      @types[type] ||= []
    end

    def to_s
      str = @base || ''
      res = @types.map do |type, segments|
        if f = self.class.formatter(type)
          str << ' ' + f.call(segments)
        else
          next if segments.empty?
          str << ' ' + self.class.sentence(segments)
        end
      end
      str
    end

    class << self

      def formatter(type)
        @formatters[type]
      end

      def register_formatter(type, &formatter)
        @formatters ||= {}
        @formatters[type] = formatter
      end

    end

    class << self

      NUMBER_SUFFIX = ['th', 'st', 'nd', 'rd', 'th', 'th', 'th', 'th', 'th', 'th']
      SPECIAL_SUFFIX = { 11 => 'th', 12 => 'th', 13 => 'th', 14 => 'th' } 
 
      # influenced by ActiveSupport's to_sentence
      def sentence(array)
        case array.length
        when 0 ; ''
        when 1 ; array[0].to_s
        when 2 ; "#{array[0]} and #{array[1]}"
        else ; "#{array[0...-1].join(', ')}, and #{array[-1]}"
        end
      end

      def nice_number(number)
        if number == -1
          'last'
        elsif number < -1
          suffix = SPECIAL_SUFFIX.include?(number) ?
            SPECIAL_SUFFIX[number] : NUMBER_SUFFIX[number.abs % 10]
          number.abs.to_s << suffix << ' to last'
        else
          suffix = SPECIAL_SUFFIX.include?(number) ?
            SPECIAL_SUFFIX[number] : NUMBER_SUFFIX[number.abs % 10]
          number.to_s << suffix  
        end
      end

    end
  
  end

end
