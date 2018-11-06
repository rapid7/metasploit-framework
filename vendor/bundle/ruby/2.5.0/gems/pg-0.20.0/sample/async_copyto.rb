#!/usr/bin/env ruby

require 'pg'
require 'stringio'

# Using COPY asynchronously

$stderr.puts "Opening database connection ..."
conn = PG.connect( :dbname => 'test' )
conn.setnonblocking( true )

socket = conn.socket_io

$stderr.puts "Running COPY command ..."
buf = ''
conn.transaction do
	conn.send_query( "COPY logs TO STDOUT WITH csv" )
	buf = nil

	# #get_copy_data returns a row if there's a whole one to return, false
	# if there isn't one but the COPY is still running, or nil when it's
	# finished.
	begin
		$stderr.puts "COPY loop"
		conn.consume_input
		while conn.is_busy
			$stderr.puts "  ready loop"
			select( [socket], nil, nil, 5.0 ) or
				raise "Timeout (5s) waiting for query response."
			conn.consume_input
		end

		buf = conn.get_copy_data
		$stdout.puts( buf ) if buf
	end until buf.nil?
end

conn.finish

