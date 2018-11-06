# PP subclass for streaming inspect output in color.
class Pry
  class ColorPrinter < ::PP
    OBJ_COLOR = begin
      code = CodeRay::Encoders::Terminal::TOKEN_COLORS[:keyword]
      if code.start_with? "\e"
        code
      else
        "\e[0m\e[0;#{code}m"
      end
    end

    CodeRay::Encoders::Terminal::TOKEN_COLORS[:comment][:self] = "\e[1;34m"

    def self.pp(obj, out = $>, width = 79, newline = "\n")
      q = ColorPrinter.new(out, width, newline)
      q.guard_inspect_key { q.pp obj }
      q.flush
      out << "\n"
    end

    def text(str, width = str.length)
      # Don't recolorize output with color [Issue #751]
      if str.include?("\e[")
        super "#{str}\e[0m", width
      elsif str.start_with?('#<') || str == '=' || str == '>'
        super highlight_object_literal(str), width
      else
        super CodeRay.scan(str, :ruby).term, width
      end
    end

    def pp(obj)
      if String === obj
        # Avoid calling Ruby 2.4+ String#pretty_print that prints multiline
        # Strings prettier
        text(obj.inspect)
      else
        super
      end
    rescue => e
      raise if e.is_a? Pry::Pager::StopPaging
      begin
        str = obj.inspect
      rescue Exception 
        # Read the class name off of the singleton class to provide a default
        # inspect.
        singleton = class << obj; self; end
        ancestors = Pry::Method.safe_send(singleton, :ancestors)
        klass  = ancestors.reject { |k| k == singleton }.first
        obj_id = obj.__id__.to_s(16) rescue 0
        str    = "#<#{klass}:0x#{obj_id}>"
      end

      text highlight_object_literal(str)
    end

    private

    def highlight_object_literal(object_literal)
      "#{OBJ_COLOR}#{object_literal}\e[0m"
    end
  end
end
