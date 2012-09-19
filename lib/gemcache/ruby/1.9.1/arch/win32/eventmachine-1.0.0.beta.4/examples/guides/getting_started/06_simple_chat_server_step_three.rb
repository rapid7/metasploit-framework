#!/usr/bin/env ruby

require 'rubygems' # or use Bundler.setup
require 'eventmachine'

class SimpleChatServer < EM::Connection

  @@connected_clients = Array.new


  attr_reader :username


  #
  # EventMachine handlers
  #

  def post_init
    @username = nil

    puts "A client has connected..."
    ask_username
  end

  def unbind
    @@connected_clients.delete(self)
    puts "A client has left..."
  end

  def receive_data(data)
    if entered_username?
      handle_chat_message(data.strip)
    else
      handle_username(data.strip)
    end
  end




  #
  # Username handling
  #

  def entered_username?
    !@username.nil? && !@username.empty?
  end # entered_username?

  def handle_username(input)
    if input.empty?
      send_line("Blank usernames are not allowed. Try again.")
      ask_username
    else
      @username = input
      @@connected_clients.push(self)
      self.other_peers.each { |c| c.send_data("#{@username} has joined the room\n") }
      puts "#{@username} has joined"

      self.send_line("[info] Ohai, #{@username}")
    end
  end # handle_username(input)

  def ask_username
    self.send_line("[info] Enter your username:")
  end # ask_username



  #
  # Message handling
  #

  def handle_chat_message(msg)
    raise NotImplementedError
  end



  #
  # Helpers
  #

  def other_peers
    @@connected_clients.reject { |c| self == c }
  end # other_peers

  def send_line(line)
    self.send_data("#{line}\n")
  end # send_line(line)
end

EventMachine.run do
  # hit Control + C to stop
  Signal.trap("INT")  { EventMachine.stop }
  Signal.trap("TERM") { EventMachine.stop }

  EventMachine.start_server("0.0.0.0", 10000, SimpleChatServer)
end
