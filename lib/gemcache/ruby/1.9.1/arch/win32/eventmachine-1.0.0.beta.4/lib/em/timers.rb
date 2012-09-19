module EventMachine
  # Creates a one-time timer
  #
  #  timer = EventMachine::Timer.new(5) do
  #    # this will never fire because we cancel it
  #  end
  #  timer.cancel
  #
  class Timer
    # Create a new timer that fires after a given number of seconds
    def initialize interval, callback=nil, &block
      @signature = EventMachine::add_timer(interval, callback || block)
    end

    # Cancel the timer
    def cancel
      EventMachine.send :cancel_timer, @signature
    end
  end

  # Creates a periodic timer
  #
  # @example
  #  n = 0
  #  timer = EventMachine::PeriodicTimer.new(5) do
  #    puts "the time is #{Time.now}"
  #    timer.cancel if (n+=1) > 5
  #  end
  #
  class PeriodicTimer
    # Create a new periodic timer that executes every interval seconds
    def initialize interval, callback=nil, &block
      @interval = interval
      @code = callback || block
      @cancelled = false
      @work = method(:fire)
      schedule
    end

    # Cancel the periodic timer
    def cancel
      @cancelled = true
    end

    # Fire the timer every interval seconds
    attr_accessor :interval

    # @private
    def schedule
      EventMachine::add_timer @interval, @work
    end

    # @private
    def fire
      unless @cancelled
        @code.call
        schedule
      end
    end
  end
end
