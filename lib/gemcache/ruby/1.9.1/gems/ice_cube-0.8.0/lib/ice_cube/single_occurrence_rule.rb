module IceCube

  class SingleOccurrenceRule < Rule

    attr_reader :time

    def initialize(time)
      @time = time
    end

    # Always terminating
    def terminating?
      true
    end

    def next_time(t, schedule, closing_time)
      unless closing_time && closing_time < t
        time if time >= t
      end
    end

    def to_hash
      { :time => time }
    end

  end

end
