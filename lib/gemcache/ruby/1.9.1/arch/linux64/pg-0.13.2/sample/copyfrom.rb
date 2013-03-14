#!/usr/bin/env ruby

require 'pg'
require 'stringio'

$stderr.puts "Opening database connection ..."
conn = PG.connect( :dbname => 'test' )

conn.exec( <<END_SQL )
DROP TABLE IF EXISTS logs;
CREATE TABLE logs (
	client_ip inet,
	username text,
	ts timestamp,
	request text,
	status smallint,
	bytes int
);
END_SQL

copy_data = StringIO.new( <<"END_DATA" )
"127.0.0.1","","30/Aug/2010:08:21:24 -0700","GET /manual/ HTTP/1.1",404,205
"127.0.0.1","","30/Aug/2010:08:21:24 -0700","GET /favicon.ico HTTP/1.1",404,209
"127.0.0.1","","30/Aug/2010:08:21:24 -0700","GET /favicon.ico HTTP/1.1",404,209
"127.0.0.1","","30/Aug/2010:08:22:29 -0700","GET /manual/ HTTP/1.1",200,11094
"127.0.0.1","","30/Aug/2010:08:22:38 -0700","GET /manual/index.html HTTP/1.1",200,725
"127.0.0.1","","30/Aug/2010:08:27:56 -0700","GET /manual/ HTTP/1.1",200,11094
"127.0.0.1","","30/Aug/2010:08:27:57 -0700","GET /manual/ HTTP/1.1",200,11094
"127.0.0.1","","30/Aug/2010:08:28:06 -0700","GET /manual/index.html HTTP/1.1",200,7709
"127.0.0.1","","30/Aug/2010:08:28:06 -0700","GET /manual/images/feather.gif HTTP/1.1",200,6471
"127.0.0.1","","30/Aug/2010:08:28:06 -0700","GET /manual/images/left.gif HTTP/1.1",200,60
"127.0.0.1","","30/Aug/2010:08:28:06 -0700","GET /manual/style/css/manual.css HTTP/1.1",200,18674
"127.0.0.1","","30/Aug/2010:08:28:06 -0700","GET /manual/style/css/manual-print.css HTTP/1.1",200,13200
"127.0.0.1","","30/Aug/2010:08:28:06 -0700","GET /manual/images/favicon.ico HTTP/1.1",200,1078
"127.0.0.1","","30/Aug/2010:08:28:06 -0700","GET /manual/style/css/manual-loose-100pc.css HTTP/1.1",200,3065
"127.0.0.1","","30/Aug/2010:08:28:14 -0700","OPTIONS * HTTP/1.0",200,0
"127.0.0.1","","30/Aug/2010:08:28:15 -0700","OPTIONS * HTTP/1.0",200,0
"127.0.0.1","","30/Aug/2010:08:28:47 -0700","GET /manual/mod/directives.html HTTP/1.1",200,33561
"127.0.0.1","","30/Aug/2010:08:28:53 -0700","GET /manual/mod/mpm_common.html HTTP/1.1",200,67683
"127.0.0.1","","30/Aug/2010:08:28:53 -0700","GET /manual/images/down.gif HTTP/1.1",200,56
"127.0.0.1","","30/Aug/2010:08:28:53 -0700","GET /manual/images/up.gif HTTP/1.1",200,57
"127.0.0.1","","30/Aug/2010:09:19:58 -0700","GET /manual/mod/mod_log_config.html HTTP/1.1",200,28307
"127.0.0.1","","30/Aug/2010:09:20:19 -0700","GET /manual/mod/core.html HTTP/1.1",200,194144
"127.0.0.1","","30/Aug/2010:16:02:56 -0700","GET /manual/ HTTP/1.1",200,11094
"127.0.0.1","","30/Aug/2010:16:03:00 -0700","GET /manual/ HTTP/1.1",200,11094
"127.0.0.1","","30/Aug/2010:16:06:16 -0700","GET /manual/mod/mod_dir.html HTTP/1.1",200,10583
"127.0.0.1","","30/Aug/2010:16:06:44 -0700","GET /manual/ HTTP/1.1",200,7709
END_DATA

### You can test the error case from the database side easily by
### changing one of the numbers at the end of one of the above rows to
### something non-numeric like "-".

$stderr.puts "Running COPY command with data ..."
buf = ''
conn.transaction do
	conn.exec( "COPY logs FROM STDIN WITH csv" )
	begin
		while copy_data.read( 256, buf )
			### Uncomment this to test error-handling for exceptions from the reader side:
			# raise Errno::ECONNRESET, "socket closed while reading"
			$stderr.puts "	sending %d bytes of data..." % [ buf.length ]
			until conn.put_copy_data( buf )
				$stderr.puts "	waiting for connection to be writable..."
				sleep 0.1
			end
		end
	rescue Errno => err
		errmsg = "%s while reading copy data: %s" % [ err.class.name, err.message ]
		conn.put_copy_end( errmsg )
	else
		conn.put_copy_end
		while res = conn.get_result
			$stderr.puts "Result of COPY is: %s" % [ res.res_status(res.result_status) ]
		end
	end
end


conn.finish

