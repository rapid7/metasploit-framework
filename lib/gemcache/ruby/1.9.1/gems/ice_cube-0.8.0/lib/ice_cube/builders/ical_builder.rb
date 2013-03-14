module IceCube

  class IcalBuilder

    ICAL_DAYS = ['SU', 'MO', 'TU', 'WE', 'TH', 'FR', 'SA']

    def initialize
      @hash = {}
    end

    def self.fixnum_to_ical_day(num)
      ICAL_DAYS[num]
    end

    def [](key)
      @hash[key] ||= []
    end

    # Build for a single rule entry
    def to_s
      arr = []
      if freq = @hash.delete('FREQ')
        arr << "FREQ=#{freq.join(',')}"
      end
      arr.concat(@hash.map do |key, value|
        if value.is_a?(Array)
          "#{key}=#{value.join(',')}"
        end
      end.compact)
      arr.join(';')
    end

    def self.ical_utc_format(time)
      time = time.dup.utc
      "#{time.strftime('%Y%m%dT%H%M%SZ')}" # utc time
    end

    def self.ical_format(time, force_utc)
      time = time.dup.utc if force_utc
      if time.utc?
        ":#{time.strftime('%Y%m%dT%H%M%SZ')}" # utc time
      else
        ";TZID=#{time.strftime('%Z:%Y%m%dT%H%M%S')}" # local time specified
      end
    end

    def self.ical_duration(duration)
      hours = duration / 3600; duration %= 3600
      minutes = duration / 60; duration %= 60
      repr = ''
      repr << "#{hours}H" if hours > 0
      repr << "#{minutes}M" if minutes > 0
      repr << "#{duration}S" if duration > 0
      "PT#{repr}"
    end

  end

end
