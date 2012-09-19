module EventMachine
  # Creates and immediately starts an EventMachine::TickLoop
  def self.tick_loop(*a, &b)
    TickLoop.new(*a, &b).start
  end

  # A TickLoop is useful when one needs to distribute amounts of work
  # throughout ticks in order to maintain response times. It is also useful for
  # simple repeated checks and metrics.
  # 
  #   # Here we run through an array one item per tick until it is empty, 
  #   # printing each element.
  #   # When the array is empty, we return :stop from the callback, and the
  #   # loop will terminate.
  #   # When the loop terminates, the on_stop callbacks will be called.
  #   EM.run do
  #     array = (1..100).to_a
  #   
  #     tickloop = EM.tick_loop do
  #       if array.empty?
  #         :stop
  #       else
  #         puts array.shift
  #       end
  #     end
  #   
  #     tickloop.on_stop { EM.stop }
  #   end
  #
  class TickLoop

    # Arguments: A callback (EM::Callback) to call each tick. If the call
    # returns +:stop+ then the loop will be stopped. Any other value is 
    # ignored.
    def initialize(*a, &b)
      @work = EM::Callback(*a, &b)
      @stops = []
      @stopped = true
    end

    # Arguments: A callback (EM::Callback) to call once on the next stop (or
    # immediately if already stopped).
    def on_stop(*a, &b)
      if @stopped
        EM::Callback(*a, &b).call
      else
        @stops << EM::Callback(*a, &b)
      end
    end

    # Stop the tick loop immediately, and call it's on_stop callbacks.
    def stop
      @stopped = true
      until @stops.empty?
        @stops.shift.call
      end
    end

    # Query if the loop is stopped.
    def stopped?
      @stopped
    end

    # Start the tick loop, will raise argument error if the loop is already
    # running.
    def start
      raise ArgumentError, "double start" unless @stopped
      @stopped = false
      schedule
    end

    private
    def schedule
      EM.next_tick do
        next if @stopped
        if @work.call == :stop
          stop
        else
          schedule
        end
      end
      self
    end
  end
end