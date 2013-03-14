# encoding: utf-8
module Mail
  module CommonField # :nodoc:

    def name=(value)
      @name = value
    end

    def name
      @name ||= nil
    end

    def value=(value)
      @length = nil
      @tree = nil
      @element = nil
      @value = value
    end

    def value
      @value
    end

    def to_s
      decoded
    end

    def default
      decoded
    end

    def field_length
      @length ||= "#{name}: #{encode(decoded)}".length
    end

    def responsible_for?( val )
      name.to_s.downcase == val.to_s.downcase
    end

    private

    def strip_field(field_name, value)
      if value.is_a?(Array)
        value
      else
        value.to_s.gsub(/#{field_name}:\s+/i, '')
      end
    end

  end
end
