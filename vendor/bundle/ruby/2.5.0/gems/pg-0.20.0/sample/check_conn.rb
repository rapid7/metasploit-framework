#!/usr/bin/env ruby
# vim: set nosta noet ts=4 sw=4:
# encoding: utf-8

require 'pg'

# This is a minimal example of a function that can test an existing PG::Connection and
# reset it if necessary.

def check_connection( conn )
	begin
		conn.exec( "SELECT 1" )
	rescue PG::Error => err
		$stderr.puts "%p while testing connection: %s" % [ err.class, err.message ]
		conn.reset
	end
end

conn = PG.connect( dbname: 'test' )
check_connection( conn )

