#!/usr/bin/env ruby
#
# Test script, demonstrating a non-poll notification for a table event.
#

BEGIN {
        require 'pathname'
        basedir = Pathname.new( __FILE__ ).expand_path.dirname.parent
        libdir = basedir + 'lib'
        $LOAD_PATH.unshift( libdir.to_s ) unless $LOAD_PATH.include?( libdir.to_s )
}

require 'pg'

TRIGGER_TABLE = %{
	CREATE TABLE IF NOT EXISTS test ( message text );
}

TRIGGER_FUNCTION = %{
CREATE OR REPLACE FUNCTION notify_test()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
    BEGIN
        NOTIFY woo;
        RETURN NULL;
    END
$$
}

DROP_TRIGGER = %{
DROP TRIGGER IF EXISTS notify_trigger ON test
}


TRIGGER = %{
CREATE TRIGGER notify_trigger
AFTER UPDATE OR INSERT OR DELETE
ON test
FOR EACH STATEMENT
EXECUTE PROCEDURE notify_test();
}

conn = PG.connect( :dbname => 'test' )

conn.exec( TRIGGER_TABLE )
conn.exec( TRIGGER_FUNCTION )
conn.exec( DROP_TRIGGER )
conn.exec( TRIGGER )

conn.exec( 'LISTEN woo' )  # register interest in the 'woo' event

notifications = []

puts "Now switch to a different term and run:",
     '',
     %{  psql test -c "insert into test values ('A message.')"},
	 ''

puts "Waiting up to 30 seconds for for an event!"
conn.wait_for_notify( 30 ) do |notify, pid|
	notifications << [ pid, notify ]
end

if notifications.empty?
	puts "Awww, I didn't see any events."
else
	puts "I got one from pid %d: %s" % notifications.first
end



