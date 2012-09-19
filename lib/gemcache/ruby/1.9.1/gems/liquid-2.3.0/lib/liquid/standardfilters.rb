require 'cgi'

module Liquid

  module StandardFilters

    # Return the size of an array or of an string
    def size(input)

      input.respond_to?(:size) ? input.size : 0
    end

    # convert a input string to DOWNCASE
    def downcase(input)
      input.to_s.downcase
    end

    # convert a input string to UPCASE
    def upcase(input)
      input.to_s.upcase
    end

    # capitalize words in the input centence
    def capitalize(input)
      input.to_s.capitalize
    end

    def escape(input)
      CGI.escapeHTML(input) rescue input
    end

    def escape_once(input)
      ActionView::Helpers::TagHelper.escape_once(input)
    rescue NameError
      input
    end

    alias_method :h, :escape

    # Truncate a string down to x characters
    def truncate(input, length = 50, truncate_string = "...")
      if input.nil? then return end
      l = length.to_i - truncate_string.length
      l = 0 if l < 0
      input.length > length.to_i ? input[0...l] + truncate_string : input
    end

    def truncatewords(input, words = 15, truncate_string = "...")
      if input.nil? then return end
      wordlist = input.to_s.split
      l = words.to_i - 1
      l = 0 if l < 0
      wordlist.length > l ? wordlist[0..l].join(" ") + truncate_string : input
    end

    # Split input string into an array of substrings separated by given pattern.
    def split(input, pattern)
      input.split(pattern)
    end

    def strip_html(input)
      input.to_s.gsub(/<script.*?<\/script>/, '').gsub(/<.*?>/, '')
    end

    # Remove all newlines from the string
    def strip_newlines(input)
      input.to_s.gsub(/\n/, '')
    end


    # Join elements of the array with certain character between them
    def join(input, glue = ' ')
      [input].flatten.join(glue)
    end

    # Sort elements of the array
    # provide optional property with which to sort an array of hashes or drops
    def sort(input, property = nil)
      ary = [input].flatten
      if property.nil?
        ary.sort
      elsif ary.first.respond_to?('[]') and !ary.first[property].nil?
        ary.sort {|a,b| a[property] <=> b[property] }
      elsif ary.first.respond_to?(property)
        ary.sort {|a,b| a.send(property) <=> b.send(property) }
      end
    end

    # map/collect on a given property
    def map(input, property)
      ary = [input].flatten
      if ary.first.respond_to?('[]') and !ary.first[property].nil?
        ary.map {|e| e[property] }
      elsif ary.first.respond_to?(property)
        ary.map {|e| e.send(property) }
      end
    end

    # Replace occurrences of a string with another
    def replace(input, string, replacement = '')
      input.to_s.gsub(string, replacement)
    end

    # Replace the first occurrences of a string with another
    def replace_first(input, string, replacement = '')
      input.to_s.sub(string, replacement)
    end

    # remove a substring
    def remove(input, string)
      input.to_s.gsub(string, '')
    end

    # remove the first occurrences of a substring
    def remove_first(input, string)
      input.to_s.sub(string, '')
    end

    # add one string to another
    def append(input, string)
      input.to_s + string.to_s
    end

    # prepend a string to another
    def prepend(input, string)
      string.to_s + input.to_s
    end

    # Add <br /> tags in front of all newlines in input string
    def newline_to_br(input)
      input.to_s.gsub(/\n/, "<br />\n")
    end

    # Reformat a date
    #
    #   %a - The abbreviated weekday name (``Sun'')
    #   %A - The  full  weekday  name (``Sunday'')
    #   %b - The abbreviated month name (``Jan'')
    #   %B - The  full  month  name (``January'')
    #   %c - The preferred local date and time representation
    #   %d - Day of the month (01..31)
    #   %H - Hour of the day, 24-hour clock (00..23)
    #   %I - Hour of the day, 12-hour clock (01..12)
    #   %j - Day of the year (001..366)
    #   %m - Month of the year (01..12)
    #   %M - Minute of the hour (00..59)
    #   %p - Meridian indicator (``AM''  or  ``PM'')
    #   %S - Second of the minute (00..60)
    #   %U - Week  number  of the current year,
    #           starting with the first Sunday as the first
    #           day of the first week (00..53)
    #   %W - Week  number  of the current year,
    #           starting with the first Monday as the first
    #           day of the first week (00..53)
    #   %w - Day of the week (Sunday is 0, 0..6)
    #   %x - Preferred representation for the date alone, no time
    #   %X - Preferred representation for the time alone, no date
    #   %y - Year without a century (00..99)
    #   %Y - Year with century
    #   %Z - Time zone name
    #   %% - Literal ``%'' character
    def date(input, format)

      if format.to_s.empty?
        return input.to_s
      end

      if ((input.is_a?(String) && !/^\d+$/.match(input.to_s).nil?) || input.is_a?(Integer)) && input.to_i > 0
        input = Time.at(input.to_i)
      end

      date = input.is_a?(String) ? Time.parse(input) : input

      if date.respond_to?(:strftime)
        date.strftime(format.to_s)
      else
        input
      end
    rescue => e
      input
    end

    # Get the first element of the passed in array
    #
    # Example:
    #    {{ product.images | first | to_img }}
    #
    def first(array)
      array.first if array.respond_to?(:first)
    end

    # Get the last element of the passed in array
    #
    # Example:
    #    {{ product.images | last | to_img }}
    #
    def last(array)
      array.last if array.respond_to?(:last)
    end

    # addition
    def plus(input, operand)
      to_number(input) + to_number(operand)
    end

    # subtraction
    def minus(input, operand)
      to_number(input) - to_number(operand)
    end

    # multiplication
    def times(input, operand)
      to_number(input) * to_number(operand)
    end

    # division
    def divided_by(input, operand)
      to_number(input) / to_number(operand)
    end

    def modulo(input, operand)
      to_number(input) % to_number(operand)
    end

    private

      def to_number(obj)
        case obj
        when Numeric
          obj
        when String
          (obj.strip =~ /^\d+\.\d+$/) ? obj.to_f : obj.to_i
        else
          0
        end
      end

  end

  Template.register_filter(StandardFilters)
end
