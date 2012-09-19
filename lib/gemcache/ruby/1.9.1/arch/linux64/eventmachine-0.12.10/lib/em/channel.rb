module EventMachine
  # Provides a simple interface to push items to a number of subscribers. The
  # channel will schedule all operations on the main reactor thread for thread
  # safe reactor operations.
  #
  # This provides a convenient way for connections to consume messages from 
  # long running code in defer, without threading issues.
  #
  #  channel = EM::Channel.new
  #  sid = channel.subscribe{ |msg| p [:got, msg] }
  #  channel.push('hello world')
  #  channel.unsubscribe(sid)
  #
  # See examples/ex_channel.rb for a detailed example.
  class Channel
    # Create a new channel
    def initialize
      @subs = {}
      @uid = 0
    end

    # Takes any arguments suitable for EM::Callback() and returns a subscriber
    # id for use when unsubscribing.
    def subscribe(*a, &b)
      name = gen_id
      EM.schedule { @subs[name] = EM::Callback(*a, &b) }
      name
    end

    # Removes this subscriber from the list.
    def unsubscribe(name)
      EM.schedule { @subs.delete name }
    end

    # Add items to the channel, which are pushed out to all subscribers.
    def push(*items)
      items = items.dup
      EM.schedule { @subs.values.each { |s| items.each { |i| s.call i } } }
    end
    alias << push

    # Receive exactly one message from the channel.
    def pop(*a, &b)
      EM.schedule {
        name = subscribe do |*args|
          unsubscribe(name)
          EM::Callback(*a, &b).call(*args)
        end
      }
    end

    private
    def gen_id # :nodoc:
      @uid += 1
    end
  end
end