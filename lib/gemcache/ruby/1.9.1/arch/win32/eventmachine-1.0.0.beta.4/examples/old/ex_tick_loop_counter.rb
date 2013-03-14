require File.dirname(__FILE__) + '/helper'

class TickCounter
  attr_reader :start_time, :count

  def initialize
    reset
    @tick_loop = EM.tick_loop(method(:tick))
  end

  def reset
    @count = 0
    @start_time = EM.current_time
  end

  def tick
    @count += 1
  end

  def rate
    @count / (EM.current_time - @start_time)
  end
end

period = 5
EM.run do
  counter = TickCounter.new
  EM.add_periodic_timer(period) do
    puts "Ticks per second: #{counter.rate} (mean of last #{period}s)"
    counter.reset
  end
end