require File.dirname(__FILE__) + '/helper'

EM.run do

  # Create a channel to push data to, this could be stocks...
  RandChannel = EM::Channel.new

  # The server simply subscribes client connections to the channel on connect,
  # and unsubscribes them on disconnect.
  class Server < EM::Connection
    def self.start(host = '127.0.0.1', port = 8000)
      EM.start_server(host, port, self)
    end

    def post_init
      @sid = RandChannel.subscribe { |m| send_data "#{m.inspect}\n" }
    end

    def unbind
      RandChannel.unsubscribe @sid
    end
  end
  Server.start

  # Two client connections, that just print what they receive.
  2.times do
    EM.connect('127.0.0.1', 8000) do |c|
      c.extend EM::P::LineText2
      def c.receive_line(line)
        puts "Subscriber: #{signature} got #{line}"
      end
      EM.add_timer(2) { c.close_connection }
    end
  end

  # This part of the example is more fake, but imagine sleep was in fact a
  # long running calculation to achieve the value.
  40.times do
    EM.defer lambda { v = sleep(rand * 2); RandChannel << [Time.now, v] }
  end

  EM.add_timer(5) { EM.stop }
end
