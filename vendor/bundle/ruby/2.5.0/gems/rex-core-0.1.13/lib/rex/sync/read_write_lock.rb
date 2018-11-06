# -*- coding: binary -*-
require 'thread'

module Rex

###
#
# This class implements a read/write lock synchronization
# primitive.  It is meant to allow for more efficient access to
# resources that are more often read from than written to and many
# times can have concurrent reader threads.  By allowing the reader
# threads to lock the resource concurrently rather than serially,
# a large performance boost can be seen.  Acquiring a write lock
# results in exclusive access to the resource and thereby prevents
# any read operations during the time that a write lock is acquired.
# Only one write lock may be acquired at a time.
#
###
class ReadWriteLock

  #
  # Initializes a reader/writer lock instance.
  #
  def initialize
    @read_sync_mutex  = Mutex.new
    @write_sync_mutex = Mutex.new
    @exclusive_mutex  = Mutex.new
    @readers          = 0
    @writer           = false
  end

  #
  # Acquires the read lock for the calling thread.
  #
  def lock_read
    read_sync_mutex.lock

    begin
      # If there are a non-zero number of readers and a
      # writer is waiting to acquire the exclusive lock,
      # free up the sync mutex temporarily and lock/unlock
      # the exclusive lock.  This is to give the writer
      # thread a chance to acquire the lock and prevents
      # it from being constantly starved.
      if ((@readers > 0) and
          (@writer))
        read_sync_mutex.unlock
        exclusive_mutex.lock
        exclusive_mutex.unlock
        read_sync_mutex.lock
      end

      # Increment the active reader count
      @readers += 1

      # If we now have just one reader, acquire the exclusive
      # lock.  Track the thread owner so that we release the
      # lock from within the same thread context later on.
      if (@readers == 1)
        exclusive_mutex.lock

        @owner = Thread.current
      end
    ensure
      read_sync_mutex.unlock
    end
  end

  #
  # Releases the read lock for the calling thread.
  #
  def unlock_read
    read_sync_mutex.lock

    begin
      unlocked = false

      # Keep looping until we've lost this thread's reader
      # lock
      while (!unlocked)
        # If there are no more readers left after this one
        if (@readers - 1 == 0)
          # If the calling thread is the owner of the exclusive
          # reader lock, then let's release it
          if (Thread.current == @owner)
            @owner = nil

            exclusive_mutex.unlock
          end
        # If there is more than one reader left and this thread is
        # the owner of the exclusive lock, then keep looping so that
        # we can eventually unlock the exclusive mutex in this thread's
        # context
        elsif (Thread.current == @owner)
          read_sync_mutex.unlock

          next
        end

        # Unlocked!
        unlocked = true

        # Decrement the active reader count
        @readers -= 1
      end
    ensure
      read_sync_mutex.unlock
    end
  end

  #
  # Acquire the exclusive write lock.
  #
  def lock_write
    write_sync_mutex.lock

    begin
      @writer = true

      exclusive_mutex.lock

      @owner  = Thread.current
    ensure
      write_sync_mutex.unlock
    end
  end

  #
  # Release the exclusive write lock.
  #
  def unlock_write
    # If the caller is not the owner of the write lock, then someone is
    # doing something broken, let's let them know.
    if (Thread.current != @owner)
      raise RuntimeError, "Non-owner calling thread attempted to release write lock", caller
    end

    # Otherwise, release the exclusive write lock
    @writer = false

    exclusive_mutex.unlock
  end

  #
  # Synchronize a block for read access.
  #
  def synchronize_read
    lock_read
    begin
      yield
    ensure
      unlock_read
    end
  end

  #
  # Synchronize a block for write access.
  #
  def synchronize_write
    lock_write
    begin
      yield
    ensure
      unlock_write
    end
  end

protected

  attr_accessor :read_sync_mutex # :nodoc:
  attr_accessor :write_sync_mutex # :nodoc:
  attr_accessor :exclusive_mutex # :nodoc:

end

end

