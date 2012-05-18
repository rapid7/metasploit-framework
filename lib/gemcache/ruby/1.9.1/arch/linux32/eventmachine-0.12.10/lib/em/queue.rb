module EventMachine
  # A cross thread, reactor scheduled, linear queue.
  #
  # This class provides a simple "Queue" like abstraction on top of the reactor
  # scheduler. It services two primary purposes:
  # * API sugar for stateful protocols
  # * Pushing processing onto the same thread as the reactor
  #
  # See examples/ex_queue.rb for a detailed example.
  #
  #  q = EM::Queue.new
  #  q.push('one', 'two', 'three')
  #  3.times do
  #    q.pop{ |msg| puts(msg) }
  #  end
  #
  class Queue
    # Create a new queue
    def initialize
      @items = []
      @popq  = []
    end

    # Pop items off the queue, running the block on the reactor thread. The pop
    # will not happen immediately, but at some point in the future, either in 
    # the next tick, if the queue has data, or when the queue is populated.
    def pop(*a, &b)
      cb = EM::Callback(*a, &b)
      EM.schedule do
        if @items.empty?
          @popq << cb
        else
          cb.call @items.shift
        end
      end
      nil # Always returns nil
    end

    # Push items onto the queue in the reactor thread. The items will not appear
    # in the queue immediately, but will be scheduled for addition during the 
    # next reactor tick.
    def push(*items)
      EM.schedule do
        @items.push(*items)
        @popq.shift.call @items.shift until @items.empty? || @popq.empty?
      end
    end

    # N.B. This is a peek, it's not thread safe, and may only tend toward 
    # accuracy.
    def empty?
      @items.empty?
    end

    # N.B. This is a peek, it's not thread safe, and may only tend toward 
    # accuracy.
    def size
      @items.size
    end
  end
end