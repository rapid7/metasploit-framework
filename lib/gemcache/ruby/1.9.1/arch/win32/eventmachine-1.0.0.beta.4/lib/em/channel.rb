module EventMachine
  # Provides a simple thread-safe way to transfer data between (typically) long running
  # tasks in {EventMachine.defer} and event loop thread.
  #
  # @example
  #
  #  channel = EventMachine::Channel.new
  #  sid     = channel.subscribe { |msg| p [:got, msg] }
  #
  #  channel.push('hello world')
  #  channel.unsubscribe(sid)
  #
  #
  class Channel
    def initialize
      @subs = {}
      @uid  = 0
    end

    # Takes any arguments suitable for EM::Callback() and returns a subscriber
    # id for use when unsubscribing.
    #
    # @return [Integer] Subscribe identifier
    # @see #unsubscribe
    def subscribe(*a, &b)
      name = gen_id
      EM.schedule { @subs[name] = EM::Callback(*a, &b) }

      name
    end

    # Removes subscriber from the list.
    #
    # @param [Integer] Subscriber identifier
    # @see #subscribe
    def unsubscribe(name)
      EM.schedule { @subs.delete name }
    end

    # Add items to the channel, which are pushed out to all subscribers.
    def push(*items)
      items = items.dup
      EM.schedule { items.each { |i| @subs.values.each { |s| s.call i } } }
    end
    alias << push

    # Fetches one message from the channel.
    def pop(*a, &b)
      EM.schedule {
        name = subscribe do |*args|
          unsubscribe(name)
          EM::Callback(*a, &b).call(*args)
        end
      }
    end

    private

    # @private
    def gen_id
      @uid += 1
    end
  end
end
