#!/usr/bin/env ruby

require 'pg'

conn = PG.connect( :dbname => 'test' )
$stderr.puts '---',
	RUBY_DESCRIPTION,
	PG.version_string( true ),
	"Server version: #{conn.server_version}",
	"Client version: #{PG.respond_to?( :library_version ) ? PG.library_version : 'unknown'}",
	'---'

result = conn.exec( "SELECT * from pg_stat_activity" )

$stderr.puts %Q{Expected this to return: ["select * from pg_stat_activity"]}
p result.field_values( 'current_query' )

