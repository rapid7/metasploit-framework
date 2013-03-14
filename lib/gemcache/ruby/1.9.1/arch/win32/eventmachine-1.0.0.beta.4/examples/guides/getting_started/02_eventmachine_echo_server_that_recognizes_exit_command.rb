#!/usr/bin/env ruby

require 'rubygems' # or use Bundler.setup
require 'eventmachine'

class EchoServer < EM::Connection
  def receive_data(data)
    if data.strip =~ /exit$/i
      EventMachine.stop
    else
      send_data(data)
    end
  end
end

EventMachine.run do
  # hit Control + C to stop
  Signal.trap("INT")  { EventMachine.stop }
  Signal.trap("TERM") { EventMachine.stop }

  EventMachine.start_server("0.0.0.0", 10000, EchoServer)
end
