require 'thread'

class Pry
  # There is one InputLock per input (such as STDIN) as two REPLs on the same
  # input makes things delirious. InputLock serializes accesses to the input so
  # that threads to not conflict with each other. The latest thread to request
  # ownership of the input wins.
  class InputLock
    class Interrupt < Exception; end

    class << self
      attr_accessor :input_locks
      attr_accessor :global_lock
    end

    self.input_locks = {}
    self.global_lock = Mutex.new

    def self.for(input)
      # XXX This method leaks memory, as we never unregister an input once we
      # are done with it. Fortunately, the leak is tiny (or so we hope).  In
      # usual scenarios, we would leak the StringIO that is passed to be
      # evaluated from the command line.
      global_lock.synchronize do
        input_locks[input] ||= Pry::InputLock.new
      end
    end

    def initialize
      @mutex = Mutex.new
      @cond = ConditionVariable.new
      @owners = []
      @interruptible = false
    end

    # Adds ourselves to the ownership list. The last one in the list may access
    # the input through interruptible_region().
    def __with_ownership(&block)
      @mutex.synchronize do
        # Three cases:
        # 1) There are no owners, in this case we are good to go.
        # 2) The current owner of the input is not reading the input (it might
        #    just be evaluating some ruby that the user typed).
        #    The current owner will figure out that it cannot go back to reading
        #    the input since we are adding ourselves to the @owners list, which
        #    in turns makes us the current owner.
        # 3) The owner of the input is in the interruptible region, reading from
        #    the input. It's safe to send an Interrupt exception to interrupt
        #    the owner. It will then proceed like in case 2).
        #    We wait until the owner sets the interruptible flag back
        #    to false, meaning that he's out of the interruptible region.
        #    Note that the owner may receive multiple interrupts since, but that
        #    should be okay (and trying to avoid it is futile anyway).
        while @interruptible
          @owners.last.raise Interrupt
          @cond.wait(@mutex)
        end
        @owners << Thread.current
      end

      block.call

    ensure
      @mutex.synchronize do
        # We are releasing any desire to have the input ownership by removing
        # ourselves from the list.
        @owners.delete(Thread.current)

        # We need to wake up the thread at the end of the @owners list, but
        # sadly Ruby doesn't allow us to choose which one we wake up, so we wake
        # them all up.
        @cond.broadcast
      end
    end

    def with_ownership(&block)
      # If we are in a nested with_ownership() call (nested pry context), we do nothing.
      nested = @mutex.synchronize { @owners.include?(Thread.current) }
      nested ? block.call : __with_ownership(&block)
    end

    def enter_interruptible_region
      @mutex.synchronize do
        # We patiently wait until we are the owner. This may happen as another
        # thread calls with_ownership() because of a binding.pry happening in
        # another thread.
        @cond.wait(@mutex) until @owners.last == Thread.current

        # We are the legitimate owner of the input. We mark ourselves as
        # interruptible, so other threads can send us an Interrupt exception
        # while we are blocking from reading the input.
        @interruptible = true
      end
    end

    def leave_interruptible_region
      @mutex.synchronize do
        # We check if we are still the owner, because we could have received an
        # Interrupt right after the following @cond.broadcast, making us retry.
        @interruptible = false if @owners.last == Thread.current
        @cond.broadcast
      end
    rescue Interrupt
      # We need to guard against a spurious interrupt delivered while we are
      # trying to acquire the lock (the rescue block is no longer in our scope).
      retry
    end

    def interruptible_region(&block)
      enter_interruptible_region

      # XXX Note that there is a chance that we get the interrupt right after
      # the readline call succeeded, but we'll never know, and we will retry the
      # call, discarding that piece of input.
      block.call

    rescue Interrupt
      # We were asked to back off. The one requesting the interrupt will be
      # waiting on the conditional for the interruptible flag to change to false.
      # Note that there can be some inefficiency, as we could immediately
      # succeed in enter_interruptible_region(), even before the one requesting
      # the ownership has the chance to register itself as an owner.
      # To mitigate the issue, we sleep a little bit.
      leave_interruptible_region
      sleep 0.01
      retry

    ensure
      leave_interruptible_region
    end
  end
end
