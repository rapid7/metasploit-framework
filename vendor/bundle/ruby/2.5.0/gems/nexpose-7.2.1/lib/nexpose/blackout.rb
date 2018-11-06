module Nexpose
  # Constants useful across the Nexpose module.
  # Configuration structure for blackouts.
  class Blackout < APIObject
    # Whether or not this blackout is enabled.
    attr_accessor :enabled
    # Valid schedule types: daily, hourly, monthly-date, monthly-day, weekly.
    attr_accessor :blackout_type
    # The repeat interval based upon type.
    attr_accessor :blackout_interval
    # Starting time of the blackout (in unix epoch with milliseconds. Example: 1464956590000)
    # The timezone is the timezone of the console. If the console timezone is not supported it defaults to utc.
    attr_accessor :blackout_start
    # The amount of time, in minutes, a blackout period should last.
    attr_accessor :blackout_duration

    def initialize(start, enabled = true, duration, type, interval)
      @blackout_start    = start
      @enabled           = enabled
      @blackout_duration = duration.to_i
      @blackout_type     = type
      @blackout_interval = interval.to_i
    end

    def self.from_hash(hash)
      repeat_blackout_hash = hash[:repeat_blackout]
      if repeat_blackout_hash.nil?
        type     = 'daily'
        interval = 0
      else
        type     = repeat_blackout_hash[:type]
        interval = repeat_blackout_hash[:interval]
      end
      new(hash[:start_date], hash[:enabled], hash[:blackout_duration], type, interval)
    end

    def to_h
      blackout_hash = { start_date: @blackout_start, enabled: @enabled, blackout_duration: @blackout_duration }
      repeat_hash   = { type: @blackout_type, interval: @blackout_interval }
      blackout_hash[:repeat_blackout] = repeat_hash
      blackout_hash
    end
  end

end
