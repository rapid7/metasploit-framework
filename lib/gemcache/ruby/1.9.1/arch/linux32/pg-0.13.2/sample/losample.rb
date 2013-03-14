#!/usr/bin/env ruby

require 'pg'

SAMPLE_WRITE_DATA = 'some sample data'
SAMPLE_EXPORT_NAME = 'lowrite.txt'

conn = PG.connect( :dbname => 'test', :host => 'localhost', :port => 5432 )
puts "dbname: " + conn.db + "\thost: " + conn.host + "\tuser: " + conn.user

# Start a transaction, as all large object functions require one.
puts "Beginning transaction"
conn.exec( 'BEGIN' )

# Test importing from a file
puts "Import test:"
puts "  importing %s" % [ __FILE__ ]
oid = conn.lo_import( __FILE__ )
puts "  imported as large object %d" % [ oid ]

# Read back 50 bytes of the imported data
puts "Read test:"
fd = conn.lo_open( oid, PG::INV_READ|PG::INV_WRITE )
conn.lo_lseek( fd, 0, PG::SEEK_SET )
buf = conn.lo_read( fd, 50 )
puts "  read: %p" % [ buf ]
puts "  read was ok!" if buf =~ /require 'pg'/

# Append some test data onto the end of the object
puts "Write test:"
conn.lo_lseek( fd, 0, PG::SEEK_END )
buf = SAMPLE_WRITE_DATA.dup
totalbytes = 0
until buf.empty?
	bytes = conn.lo_write( fd, buf )
	buf.slice!( 0, bytes )
	totalbytes += bytes
end
puts "  appended %d bytes" % [ totalbytes ]

# Now export it
puts "Export test:"
File.unlink( SAMPLE_EXPORT_NAME ) if File.exist?( SAMPLE_EXPORT_NAME )
conn.lo_export( oid, SAMPLE_EXPORT_NAME )
puts "  success!" if File.exist?( SAMPLE_EXPORT_NAME )
puts "  exported as %s (%d bytes)" % [ SAMPLE_EXPORT_NAME, File.size(SAMPLE_EXPORT_NAME) ]

conn.exec( 'COMMIT' )
puts "End of transaction."


puts 'Testing read and delete from a new transaction:'
puts '  starting a new transaction'
conn.exec( 'BEGIN' )

fd = conn.lo_open( oid, PG::INV_READ )
puts '  reopened okay.'
conn.lo_lseek( fd, 50, PG::SEEK_END )
buf = conn.lo_read( fd, 50 )
puts '  read okay.' if buf == SAMPLE_WRITE_DATA

puts 'Closing and unlinking:'
conn.lo_close( fd )
puts '  closed.'
conn.lo_unlink( oid )
puts '  unlinked.'
conn.exec( 'COMMIT' )
puts 'Done.'

