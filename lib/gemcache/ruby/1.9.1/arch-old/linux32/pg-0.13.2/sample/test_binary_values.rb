#!/usr/bin/env ruby1.9.1

require 'pg'

db = PG.connect( :dbname => 'test' )
db.exec "DROP TABLE IF EXISTS test"
db.exec "CREATE TABLE test (a INTEGER, b BYTEA)"

a = 42
b = [1, 2, 3]
db.exec "INSERT INTO test(a, b) VALUES($1::int, $2::bytea)",
	[a, {:value => b.pack('N*'), :format => 1}]

db.exec( "SELECT a::int, b::bytea FROM test LIMIT 1", [], 1 ) do |res|

	res.nfields.times do |i|
		puts "Field %d is: %s, a %s (%s) column from table %p" % [
			i,
			res.fname( i ),
			db.exec( "SELECT format_type($1,$2)", [res.ftype(i), res.fmod(1)] ).getvalue(0,0),
			res.fformat( i ).zero? ? "string" : "binary",
			res.ftable( i ),
		]
	end

	res.each do |row|
		puts "a = #{row['a'].inspect}"
		puts "a (unpacked) = #{row['a'].unpack('N*').inspect}"
		puts "b = #{row['b'].unpack('N*').inspect}"
	end
end


