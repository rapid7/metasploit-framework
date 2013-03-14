#!/usr/bin/env ruby

require 'rubygems' # or use Bundler.setup
require 'eventmachine'

class SimpleChatServer < EM::Connection

  #
  # EventMachine handlers
  #

  def post_init
    puts "A client has connected..."
  end

  def unbind
    puts "A client has left..."
  end
end

EventMachine.run do
  # hit Control + C to stop
  Signal.trap("INT")  { EventMachine.stop }
  Signal.trap("TERM") { EventMachine.stop }

  EventMachine.start_server("0.0.0.0", 10000, SimpleChatServer)
end
