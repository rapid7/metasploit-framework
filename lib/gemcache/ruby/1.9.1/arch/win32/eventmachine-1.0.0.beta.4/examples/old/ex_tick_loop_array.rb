require File.dirname(__FILE__) + '/helper'

EM.run do
  array = (1..100).to_a

  tickloop = EM.tick_loop do
    if array.empty?
      :stop
    else
      puts array.shift
    end
  end

  tickloop.on_stop { EM.stop }
end