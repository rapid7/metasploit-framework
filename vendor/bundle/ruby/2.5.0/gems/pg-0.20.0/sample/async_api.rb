#!/usr/bin/env ruby

require 'pg'

# This is a example of how to use the asynchronous API to query the
# server without blocking other threads. It's intentionally low-level;
# if you hooked up the PG::Connection#socket to some kind of reactor, you
# could make this much nicer.

TIMEOUT = 5.0 # seconds to wait for an async operation to complete

# Print 'x' continuously to demonstrate that other threads aren't
# blocked while waiting for the connection, for the query to be sent,
# for results, etc. You might want to sleep inside the loop or
# comment this out entirely for cleaner output.
progress_thread = Thread.new { loop { print 'x' } }

# Output progress messages
def output_progress( msg )
	puts "\n>>> #{msg}\n"
end

# Start the connection
output_progress "Starting connection..."
conn = PG::Connection.connect_start( :dbname => 'test' ) or
	abort "Unable to create a new connection!"
abort "Connection failed: %s" % [ conn.error_message ] if
	conn.status == PG::CONNECTION_BAD

# Now grab a reference to the underlying socket so we know when the
# connection is established
socket = conn.socket_io

# Track the progress of the connection, waiting for the socket to become readable/writable
# before polling it
poll_status = PG::PGRES_POLLING_WRITING
until poll_status == PG::PGRES_POLLING_OK ||
	  poll_status == PG::PGRES_POLLING_FAILED

	# If the socket needs to read, wait 'til it becomes readable to poll again
	case poll_status
	when PG::PGRES_POLLING_READING
		output_progress "  waiting for socket to become readable"
		select( [socket], nil, nil, TIMEOUT ) or
			raise "Asynchronous connection timed out!"

	# ...and the same for when the socket needs to write
	when PG::PGRES_POLLING_WRITING
		output_progress "  waiting for socket to become writable"
		select( nil, [socket], nil, TIMEOUT ) or
			raise "Asynchronous connection timed out!"
	end

	# Output a status message about the progress
	case conn.status
	when PG::CONNECTION_STARTED
		output_progress "  waiting for connection to be made."
	when PG::CONNECTION_MADE
		output_progress "  connection OK; waiting to send."
	when PG::CONNECTION_AWAITING_RESPONSE
		output_progress "  waiting for a response from the server."
	when PG::CONNECTION_AUTH_OK
		output_progress "  received authentication; waiting for backend start-up to finish."
	when PG::CONNECTION_SSL_STARTUP
		output_progress "  negotiating SSL encryption."
	when PG::CONNECTION_SETENV
		output_progress "  negotiating environment-driven parameter settings."
	when PG::CONNECTION_NEEDED
		output_progress "  internal state: connect() needed."
	end

	# Check to see if it's finished or failed yet
	poll_status = conn.connect_poll
end

abort "Connect failed: %s" % [ conn.error_message ] unless conn.status == PG::CONNECTION_OK

output_progress "Sending query"
conn.send_query( "SELECT * FROM pg_stat_activity" )

# Fetch results until there aren't any more
loop do
	output_progress "  waiting for a response"

	# Buffer any incoming data on the socket until a full result is ready.
	conn.consume_input
	while conn.is_busy
		select( [socket], nil, nil, TIMEOUT ) or
			raise "Timeout waiting for query response."
		conn.consume_input
	end

	# Fetch the next result. If there isn't one, the query is finished
	result = conn.get_result or break

	puts "\n\nQuery result:\n%p\n" % [ result.values ]
end

output_progress "Done."
conn.finish

if defined?( progress_thread )
	progress_thread.kill
	progress_thread.join
end

