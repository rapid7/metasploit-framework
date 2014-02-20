# -*- coding: binary -*-
module Rex

###
#
# Extended time related functions.
#
###
module ExtTime

  #
  # Convert seconds to a string that is broken down into years, days, hours,
  # minutes, and second.
  #
  def self.sec_to_s(seconds)
    parts = [ 31536000, 86400, 3600, 60, 1 ].map { |d|
      if ((c = seconds / d) > 0)
        seconds -= c.truncate * d
        c.truncate
      else
        0
      end
    }.reverse

    str = ''

    [ "sec", "min", "hour", "day", "year" ].each_with_index { |name, idx|
      next if (!parts[idx] or parts[idx] == 0)

      str = "#{parts[idx]} #{name + ((parts[idx] != 1) ? 's' :'')} " + str
    }

    str.empty? ? "0 secs" : str.strip
  end

  #
  # Converts a string in the form n years g days x hours y mins z secs.
  #
  def self.str_to_sec(str)
    fields = str.split(/ /)
    secs   = 0

    fields.each_with_index { |f, idx|
      val = 0
      case f
        when /^year/
          val = 31536000
        when /^day/
          val = 86400
        when /^hour/
          val = 3600
        when /^min/
          val = 60
        when /^sec/
          val = 1
      end

      secs += val * fields[idx-1].to_i
    }

    secs
  end

end

end
