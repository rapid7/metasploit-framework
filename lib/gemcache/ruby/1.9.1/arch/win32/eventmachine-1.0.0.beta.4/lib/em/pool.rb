module EventMachine
  # = EventMachine::Pool
  #
  # A simple async resource pool based on a resource and work queue. Resources
  # are enqueued and work waits for resources to become available.
  #
  # Example:
  #
  #    EM.run do
  #      pool  = EM::Pool.new
  #      spawn = lambda { pool.add EM::HttpRequest.new('http://example.org') }
  #      10.times { spawn[] }
  #      done, scheduled = 0, 0
  #    
  #      check = lambda do
  #        done += 1
  #        if done >= scheduled
  #          EM.stop
  #        end
  #      end
  #    
  #      pool.on_error { |conn| spawn[] }
  #    
  #      100.times do
  #        pool.perform do |conn|
  #          req = conn.get :path => '/', :keepalive => true
  #    
  #          req.callback do
  #            p [:success, conn.object_id, i, req.response.size]
  #            check[]
  #          end
  #    
  #          req.errback { check[] }
  #    
  #          req
  #        end
  #      end
  #    end
  #
  # Resources are expected to be controlled by an object responding to a
  # deferrable/completion style API with callback and errback blocks.
  #
  class Pool

    def initialize
      @resources = EM::Queue.new
      @removed = []
      @contents = []
      @on_error = nil
    end

    def add resource
      @contents << resource
      requeue resource
    end

    def remove resource
      @contents.delete resource
      @removed << resource
    end

    # Returns a list for introspection purposes only. You should *NEVER* call
    # modification or work oriented methods on objects in this list. A good
    # example use case is periodic statistics collection against a set of
    # connection resources.
    #
    # For example: 
    #     pool.contents.inject(0) { |sum, connection| connection.num_bytes }
    def contents
      @contents.dup
    end

    # Define a default catch-all for when the deferrables returned by work
    # blocks enter a failed state. By default all that happens is that the
    # resource is returned to the pool. If on_error is defined, this block is
    # responsible for re-adding the resource to the pool if it is still usable.
    # In other words, it is generally assumed that on_error blocks explicitly
    # handle the rest of the lifetime of the resource.
    def on_error *a, &b
      @on_error = EM::Callback(*a, &b)
    end

    # Perform a given #call-able object or block. The callable object will be
    # called with a resource from the pool as soon as one is available, and is
    # expected to return a deferrable.
    # 
    # The deferrable will have callback and errback added such that when the
    # deferrable enters a finished state, the object is returned to the pool.
    #
    # If on_error is defined, then objects are not automatically returned to the
    # pool.
    def perform(*a, &b)
      work = EM::Callback(*a, &b)

      @resources.pop do |resource|
        if removed? resource
          @removed.delete resource
          reschedule work
        else
          process work, resource
        end
      end
    end
    alias reschedule perform

    # A peek at the number of enqueued jobs waiting for resources
    def num_waiting
      @resources.num_waiting
    end

    # Removed will show resources in a partial pruned state. Resources in the
    # removed list may not appear in the contents list if they are currently in
    # use.
    def removed? resource
      @removed.include? resource
    end

    protected
    def requeue resource
      @resources.push resource
    end

    def failure resource
      if @on_error
        @contents.delete resource
        @on_error.call resource
        # Prevent users from calling a leak.
        @removed.delete resource
      else
        requeue resource
      end
    end

    def completion deferrable, resource
      deferrable.callback { requeue resource }
      deferrable.errback  { failure resource }
    end

    def process work, resource
      deferrable = work.call resource
      if deferrable.kind_of?(EM::Deferrable)
        completion deferrable, resource
      else
        raise ArgumentError, "deferrable expected from work"
      end
    rescue Exception
      failure resource
      raise
    end
  end
end
