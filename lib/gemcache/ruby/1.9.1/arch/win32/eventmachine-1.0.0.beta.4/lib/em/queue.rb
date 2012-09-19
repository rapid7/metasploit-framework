module EventMachine
  # A cross thread, reactor scheduled, linear queue.
  #
  # This class provides a simple queue abstraction on top of the reactor
  # scheduler. It services two primary purposes:
  #
  # * API sugar for stateful protocols
  # * Pushing processing onto the reactor thread
  #
  # @example
  #
  #  q = EM::Queue.new
  #  q.push('one', 'two', 'three')
  #  3.times do
  #    q.pop { |msg| puts(msg) }
  #  end
  #
  class Queue
    def initialize
      @items = []
      @popq  = []
    end

    # Pop items off the queue, running the block on the reactor thread. The pop
    # will not happen immediately, but at some point in the future, either in
    # the next tick, if the queue has data, or when the queue is populated.
    #
    # @return [NilClass] nil
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
    alias :<< :push

    # @return [Boolean]
    # @note This is a peek, it's not thread safe, and may only tend toward accuracy.
    def empty?
      @items.empty?
    end

    # @return [Integer] Queue size
    # @note This is a peek, it's not thread safe, and may only tend toward accuracy.
    def size
      @items.size
    end

    # @return [Integer] Waiting size
    # @note This is a peek at the number of jobs that are currently waiting on the Queue
    def num_waiting
      @popq.size
    end

  end # Queue
end # EventMachine
