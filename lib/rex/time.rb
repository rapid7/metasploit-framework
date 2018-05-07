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
      parts = [31536000, 86400, 3600, 60, 1].map do |d|
        if (c = seconds / d) > 0
          seconds -= c.truncate * d
          c.truncate
        else
          0
        end
      end

      str = ''

      ['year', 'day', 'hour', 'min', 'sec'].each_with_index do |name, idx|
        next if !parts[idx] || parts[idx].zero?

        str << "#{parts[idx]} #{name + ((parts[idx] != 1) ? 's' : '')} "
      end

      str.empty? ? "0 secs" : str.strip
    end
  end
end
