# -*- coding: binary -*-
require 'timeout'

module Rex

###
#
# This module provides a set of methods for performing various blocking
# operations in a manner that is compatible with ruby style threads.
#
###
module ThreadSafe

  DefaultCycle = 0.2

  #
  # Wraps calls to select with a lower timeout period and does the
  # calculations to walk down to zero timeout.  This has a little room for
  # improvement in that it should probably check how much time actually
  # elapsed during the select call considering ruby threading wont be exactly
  # accurate perhaps.
  #
  def self.select(rfd = nil, wfd = nil, efd = nil, t = nil)
    left = t

    # Immediately raise a StreamClosedError if the socket was closed. This
    # prevents a bad fd from being passed downstream and solves an issue
    # with Ruby on Windows.
    rfd.each { |fd| raise StreamClosedError.new(fd) if (fd.closed?)	} if rfd

    begin
      orig_size = rfd.length if (rfd)

      # Poll the set supplied to us at least once.
      begin
        rv = ::IO.select(rfd, wfd, efd, DefaultCycle)
      rescue ::IOError, ::Errno::EBADF, ::Errno::ENOTSOCK
        # If a stream was detected as being closed, re-raise the error as
        # a StreamClosedError with the specific file descriptor that was
        # detected as being closed.  This is to better handle the case of
        # a closed socket being detected so that it can be cleaned up and
        # removed.
        rfd.each { |fd| raise StreamClosedError.new(fd) if (fd.closed?)	} if rfd

        # If the original rfd length is not the same as the current
        # length, then the list may have been altered and as such may not
        # contain the socket that caused the IOError.  This is a bad way
        # to do this since it's possible that the array length could be
        # back to the size that it was originally and yet have had the
        # socket that caused the IOError to be removed.
        return nil if (rfd and rfd.length != orig_size)

        # Re-raise the exception since we didn't handle it here.
        raise $!
#			rescue ::Exception => e
#			$stderr.puts "SELECT(#{t}) #{[rfd,wfd,efd].inspect} #{e.class} #{e} #{e.backtrace}"
      end

      return rv if (rv)

      # Decrement the amount of time left by the polling cycle
      left -= DefaultCycle if (left)

      # Keep chugging until we run out of time, if time was supplied.
    end while ((left == nil) or (left > 0))

    # Nothin.
    nil
  end

  #
  # Simulates a sleep operation by selecting on nil until a timeout period
  # expires.
  #
  def self.sleep(seconds=nil)
    self.Rex.sleep(seconds)

    seconds
  end

end

end
