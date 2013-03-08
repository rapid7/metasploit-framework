# -*- coding: binary -*-
module ActiveRecord
module ConnectionAdapters
class ConnectionPool


      # XXX: This fixes the logic around whether a connection allocated is "fresh"
      #      AR incorrectly assumed that if any connection was established, it should
      #      no longer free the allocated connection.

      # Check to see if there is an active thread connection
      def active_thread_connection?(with_id = current_connection_id)
        @reserved_connections.has_key?(with_id)
      end

      # If a connection already exists yield it to the block. If no connection
      # exists checkout a connection, yield it to the block, and checkin the
      # connection when finished.
      def with_connection
        connection_id = current_connection_id
        fresh_connection = true unless active_thread_connection?(connection_id)
        yield connection
      ensure
        release_connection(connection_id) if fresh_connection
      end


      # XXX: This allows the wait_timeout parameter in the database specification
      #      to use wall time vs a single @queue.wait() call to determine when
      #      it should look for an available connection. This is important with
      #      heavy threading and can be used to buffer spikes when a large number
      #      of threads need their own connection.

      # Check-out a database connection from the pool, indicating that you want
      # to use it. You should call #checkin when you no longer need this.
      #
      # This is done by either returning an existing connection, or by creating
      # a new connection. If the maximum number of connections for this pool has
      # already been reached, but the pool is empty (i.e. they're all being used),
      # then this method will wait until a thread has checked in a connection.
      # The wait time is bounded however: if no connection can be checked out
      # within the timeout specified for this pool, then a ConnectionTimeoutError
      # exception will be raised.
      #
      # Returns: an AbstractAdapter object.
      #
      # Raises:
      # - ConnectionTimeoutError: no connection can be obtained from the pool
      #   within the timeout period.
      def checkout
        # Checkout an available connection
        checkout_time = Time.now.to_i
        loop do
          synchronize do
            conn = @connections.find { |c| c.lease }

            unless conn
              if @connections.size < @size
                conn = checkout_new_connection
                conn.lease
              end
            end

            if conn
              checkout_and_verify conn
              return conn
            end

            # Wait up to five seconds at a time for a yield
            @queue.wait(5)

            if(active_connections.size < @connections.size)
              next
            else
              clear_stale_cached_connections!
              if @size == active_connections.size and (Time.now.to_i - @timeout) > checkout_time
                raise ConnectionTimeoutError, "could not obtain a database connection#{" within #{@timeout} seconds" if @timeout}. The max pool size is currently #{@size}; consider increasing it or the wait_timeout parameter"
              end
            end
          end
        end
      end



end
end
end
