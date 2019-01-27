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
      return "0 secs" if seconds.to_i <= 0
      [[31536000, 'year'], [86400, 'day'], [3600, 'hour'], [60, 'min'], [1, 'sec']].map! { |count, name|
        if (c = seconds / count) > 0
          c = c.truncate
          seconds -= c * count
          if c == 1
            "#{c} #{name}"
          elsif c > 1
            "#{c} #{name}s"
          end
        end
      }.compact.join(' ')
    end
  end
end
