#!/usr/bin/env ruby

require 'pg'

$stdout.sync = true

# This is a example of how to mix and match synchronous and async APIs. In this case,
# the connection to the server is made syncrhonously, and then queries are 
# asynchronous.

TIMEOUT = 5.0 # seconds to wait for an async operation to complete
CONN_OPTS = {
	:host     => 'localhost',
	:dbname   => 'test',
}

# Output progress messages
def output_progress( msg )
	puts ">>> #{msg}\n"
end

# Start the (synchronous) connection
output_progress "Starting connection..."
conn = PG.connect( CONN_OPTS ) or abort "Unable to create a new connection!"

abort "Connect failed: %s" % [ conn.error_message ] unless conn.status == PG::CONNECTION_OK

# Now grab a reference to the underlying socket to select() on while the query is running
socket = IO.for_fd( conn.socket )

# Send the (asynchronous) query
output_progress "Sending query"
conn.send_query( "SELECT * FROM pg_stat_activity" )

# Fetch results until there aren't any more
loop do
	output_progress "  waiting for a response"

	# Buffer any incoming data on the socket until a full result is ready. 
	conn.consume_input
	while conn.is_busy
		output_progress "  waiting for data to be available on %p..." % [ socket ]
		select( [socket], nil, nil, TIMEOUT ) or
			raise "Timeout waiting for query response."
		conn.consume_input
	end

	# Fetch the next result. If there isn't one, the query is finished
	result = conn.get_result or break

	output_progress "Query result:\n%p\n" % [ result.values ]
end

output_progress "Done."
conn.finish

