#!/usr/bin/env ruby

require 'pg'

# An example of how to use SQL cursors. This is mostly a straight port of
# the cursor portion of testlibpq.c from src/test/examples.

$stderr.puts "Opening database connection ..."
conn = PG.connect( :dbname => 'test' )

#
conn.transaction do
    conn.exec( "DECLARE myportal CURSOR FOR select * from pg_database" )
    res = conn.exec( "FETCH ALL IN myportal" )

    puts res.fields.collect {|fname| "%-15s" % [fname] }.join( '' )
    res.values.collect do |row|
        puts row.collect {|col| "%-15s" % [col] }.join( '' )
    end
end

