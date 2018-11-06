module EventMachine
  # = EventMachine::ThreadedResource
  #
  # A threaded resource is a "quick and dirty" wrapper around the concept of
  # wiring up synchronous code into a standard EM::Pool. This is useful to keep
  # interfaces coherent and provide a simple approach at "making an interface
  # async-ish".
  #
  # General usage is to wrap libraries that do not support EventMachine, or to
  # have a specific number of dedicated high-cpu worker resources.
  #
  # == Basic Usage example
  #
  # This example requires the cassandra gem. The cassandra gem contains an
  # EventMachine interface, but it's sadly Fiber based and thus only works on
  # 1.9. It also requires (potentially) complex stack switching logic to reach
  # completion of nested operations. By contrast this approach provides a block
  # in which normal synchronous code can occur, but makes no attempt to wire the
  # IO into EventMachines C++ IO implementations, instead relying on the reactor
  # pattern in rb_thread_select.
  #
  #    cassandra_dispatcher = ThreadedResource.new do
  #      Cassandra.new('allthethings', '127.0.0.1:9160')
  #    end
  #
  #    pool = EM::Pool.new
  #
  #    pool.add cassandra_dispatcher
  #
  #    # If we don't care about the result:
  #    pool.perform do |dispatcher|
  #      # The following block executes inside a dedicated thread, and should not
  #      # access EventMachine things:
  #      dispatcher.dispatch do |cassandra|
  #        cassandra.insert(:Things, '10', 'stuff' => 'things')
  #      end
  #    end
  #
  #    # Example where we care about the result:
  #    pool.perform do |dispatcher|
  #      # The dispatch block is executed in the resources thread.
  #      completion = dispatcher.dispatch do |cassandra|
  #        cassandra.get(:Things, '10', 'stuff')
  #      end
  #
  #      # This block will be yielded on the EM thread:
  #      completion.callback do |result|
  #        EM.do_something_with(result)
  #      end
  #
  #      completion
  #    end
  class ThreadedResource

    # The block should return the resource that will be yielded in a dispatch.
    def initialize
      @resource = yield

      @running = true
      @queue   = ::Queue.new
      @thread  = Thread.new do
        @queue.pop.call while @running
      end
    end

    # Called on the EM thread, generally in a perform block to return a
    # completion for the work.
    def dispatch
      completion = EM::Completion.new
      @queue << lambda do
        begin
          result = yield @resource
          completion.succeed result
        rescue => e
          completion.fail e
        end
      end
      completion
    end

    # Kill the internal thread. should only be used to cleanup - generally
    # only required for tests.
    def shutdown
      @running = false
      @queue << lambda {}
      @thread.join
    end

  end
end
