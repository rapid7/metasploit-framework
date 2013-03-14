#!/usr/bin/env rspec
#encoding: utf-8

BEGIN {
	require 'pathname'

	basedir = Pathname( __FILE__ ).dirname.parent.parent
	libdir = basedir + 'lib'

	$LOAD_PATH.unshift( basedir.to_s ) unless $LOAD_PATH.include?( basedir.to_s )
	$LOAD_PATH.unshift( libdir.to_s ) unless $LOAD_PATH.include?( libdir.to_s )
}

require 'rspec'
require 'spec/lib/helpers'
require 'timeout'
require 'pg'

describe PG::Connection do

	before( :all ) do
		@conn = setup_testing_db( "PG_Connection" )
	end

	before( :each ) do
		@conn.exec( 'BEGIN' ) unless example.metadata[:without_transaction]
	end

	after( :each ) do
		@conn.exec( 'ROLLBACK' ) unless example.metadata[:without_transaction]
	end

	after( :all ) do
		teardown_testing_db( @conn )
	end


	#
	# Examples
	#

	it "can create a connection option string from a Hash of options" do
		optstring = described_class.parse_connect_args( 
			:host => 'pgsql.example.com',
			:dbname => 'db01',
			'sslmode' => 'require'
		  )

		optstring.should be_a( String )
		optstring.should =~ /(^|\s)host='pgsql.example.com'/
		optstring.should =~ /(^|\s)dbname='db01'/
		optstring.should =~ /(^|\s)sslmode='require'/
	end

	it "can create a connection option string from positional parameters" do
		optstring = described_class.parse_connect_args( 'pgsql.example.com', nil, '-c geqo=off', nil, 
		                                       'sales' )

		optstring.should be_a( String )
		optstring.should =~ /(^|\s)host='pgsql.example.com'/
		optstring.should =~ /(^|\s)dbname='sales'/
		optstring.should =~ /(^|\s)options='-c geqo=off'/
		
		optstring.should_not =~ /port=/
		optstring.should_not =~ /tty=/
	end

	it "can create a connection option string from a mix of positional and hash parameters" do
		optstring = described_class.parse_connect_args( 'pgsql.example.com',
		                                       :dbname => 'licensing', :user => 'jrandom' )

		optstring.should be_a( String )
		optstring.should =~ /(^|\s)host='pgsql.example.com'/
		optstring.should =~ /(^|\s)dbname='licensing'/
		optstring.should =~ /(^|\s)user='jrandom'/
	end

	it "escapes single quotes and backslashes in connection parameters" do
		described_class.parse_connect_args( "DB 'browser' \\" ).should == "host='DB \\'browser\\' \\\\'"

	end

	it "connects with defaults if no connection parameters are given" do
		described_class.parse_connect_args.should == ''
	end

	it "connects successfully with connection string" do
		tmpconn = described_class.connect(@conninfo)
		tmpconn.status.should== PG::CONNECTION_OK
		tmpconn.finish
	end

	it "connects using 7 arguments converted to strings" do
		tmpconn = described_class.connect('localhost', @port, nil, nil, :test, nil, nil)
		tmpconn.status.should== PG::CONNECTION_OK
		tmpconn.finish
	end

	it "connects using a hash of connection parameters" do
		tmpconn = described_class.connect(
			:host => 'localhost',
			:port => @port,
			:dbname => :test)
		tmpconn.status.should== PG::CONNECTION_OK
		tmpconn.finish
	end

	it "raises an exception when connecting with an invalid number of arguments" do
		expect {
			described_class.connect( 1, 2, 3, 4, 5, 6, 7, 'extra' )
		}.to raise_error( ArgumentError, /extra positional parameter/i )
	end


	it "can connect asynchronously" do
		tmpconn = described_class.connect_start( @conninfo )
		tmpconn.should be_a( described_class )
		socket = IO.for_fd( tmpconn.socket )
		status = tmpconn.connect_poll

		while status != PG::PGRES_POLLING_OK
			if status == PG::PGRES_POLLING_READING
				select( [socket], [], [], 5.0 ) or
					raise "Asynchronous connection timed out!"

			elsif status == PG::PGRES_POLLING_WRITING
				select( [], [socket], [], 5.0 ) or
					raise "Asynchronous connection timed out!"
			end
			status = tmpconn.connect_poll
		end

		tmpconn.status.should == PG::CONNECTION_OK
		tmpconn.finish
	end

	it "can connect asynchronously for the duration of a block" do
		conn = nil

		described_class.connect_start(@conninfo) do |tmpconn|
			tmpconn.should be_a( described_class )
			conn = tmpconn
			socket = IO.for_fd(tmpconn.socket)
			status = tmpconn.connect_poll

			while status != PG::PGRES_POLLING_OK
				if status == PG::PGRES_POLLING_READING
					if(not select([socket],[],[],5.0))
						raise "Asynchronous connection timed out!"
					end
				elsif(status == PG::PGRES_POLLING_WRITING)
					if(not select([],[socket],[],5.0))
						raise "Asynchronous connection timed out!"
					end
				end
				status = tmpconn.connect_poll
			end

			tmpconn.status.should == PG::CONNECTION_OK
		end

		conn.should be_finished()
	end

	it "doesn't leave stale server connections after finish" do
		described_class.connect(@conninfo).finish
		sleep 0.5
		res = @conn.exec(%[SELECT COUNT(*) AS n FROM pg_stat_activity
							WHERE usename IS NOT NULL])
		# there's still the global @conn, but should be no more
		res[0]['n'].should == '1'
	end


	EXPECTED_TRACE_OUTPUT = %{
		To backend> Msg Q
		To backend> "SELECT 1 AS one"
		To backend> Msg complete, length 21
		From backend> T
		From backend (#4)> 28
		From backend (#2)> 1
		From backend> "one"
		From backend (#4)> 0
		From backend (#2)> 0
		From backend (#4)> 23
		From backend (#2)> 4
		From backend (#4)> -1
		From backend (#2)> 0
		From backend> D
		From backend (#4)> 11
		From backend (#2)> 1
		From backend (#4)> 1
		From backend (1)> 1
		From backend> C
		From backend (#4)> 13
		From backend> "SELECT 1"
		From backend> Z
		From backend (#4)> 5
		From backend> Z
		From backend (#4)> 5
		From backend> T
		}.gsub( /^\t{2}/, '' ).lstrip

	unless RUBY_PLATFORM =~ /mswin|mingw/
		it "trace and untrace client-server communication" do
			# be careful to explicitly close files so that the
			# directory can be removed and we don't have to wait for
			# the GC to run.
			trace_file = TEST_DIRECTORY + "test_trace.out"
			trace_io = trace_file.open( 'w', 0600 )
			@conn.trace( trace_io )
			trace_io.close

			res = @conn.exec("SELECT 1 AS one")
			@conn.untrace

			res = @conn.exec("SELECT 2 AS two")

			trace_data = trace_file.read

			expected_trace_output = EXPECTED_TRACE_OUTPUT.dup
			# For PostgreSQL < 9.0, the output will be different:
			# -From backend (#4)> 13
			# -From backend> "SELECT 1"
			# +From backend (#4)> 11
			# +From backend> "SELECT"
			if @conn.server_version < 90000
				expected_trace_output.sub!( /From backend \(#4\)> 13/, 'From backend (#4)> 11' )
				expected_trace_output.sub!( /From backend> "SELECT 1"/, 'From backend> "SELECT"' )
			end

			trace_data.should == expected_trace_output
		end
	end

	it "allows a query to be cancelled" do
		error = false
		@conn.send_query("SELECT pg_sleep(1000)")
		@conn.cancel
		tmpres = @conn.get_result
		if(tmpres.result_status != PG::PGRES_TUPLES_OK)
			error = true
		end
		error.should == true
	end

	it "automatically rolls back a transaction started with described_class#transaction if an exception " +
	   "is raised" do
		# abort the per-example transaction so we can test our own
		@conn.exec( 'ROLLBACK' )

		res = nil
		@conn.exec( "CREATE TABLE pie ( flavor TEXT )" )

		expect {
			res = @conn.transaction do
				@conn.exec( "INSERT INTO pie VALUES ('rhubarb'), ('cherry'), ('schizophrenia')" )
				raise "Oh noes! All pie is gone!"
			end
		}.to raise_exception( RuntimeError, /all pie is gone/i )

		res = @conn.exec( "SELECT * FROM pie" )
		res.ntuples.should == 0
	end

	it "not read past the end of a large object" do
		@conn.transaction do
			oid = @conn.lo_create( 0 )
			fd = @conn.lo_open( oid, PG::INV_READ|PG::INV_WRITE )
			@conn.lo_write( fd, "foobar" )
			@conn.lo_read( fd, 10 ).should be_nil()
			@conn.lo_lseek( fd, 0, PG::SEEK_SET )
			@conn.lo_read( fd, 10 ).should == 'foobar'
		end
	end


	it "can wait for NOTIFY events" do
		@conn.exec( 'ROLLBACK' )
		@conn.exec( 'LISTEN woo' )

		pid = fork do
			begin
				conn = described_class.connect( @conninfo )
				sleep 1
				conn.exec( 'NOTIFY woo' )
			ensure
				conn.finish
				exit!
			end
		end

		@conn.wait_for_notify( 10 ).should == 'woo'
		@conn.exec( 'UNLISTEN woo' )

		Process.wait( pid )
	end

	it "calls a block for NOTIFY events if one is given" do
		@conn.exec( 'ROLLBACK' )
		@conn.exec( 'LISTEN woo' )

		pid = fork do
			begin
				conn = described_class.connect( @conninfo )
				sleep 1
				conn.exec( 'NOTIFY woo' )
			ensure
				conn.finish
				exit!
			end
		end

		eventpid = event = nil
		@conn.wait_for_notify( 10 ) {|*args| event, eventpid = args }
		event.should == 'woo'
		eventpid.should be_an( Integer )

		@conn.exec( 'UNLISTEN woo' )

		Process.wait( pid )
	end

	it "doesn't collapse sequential notifications" do
		@conn.exec( 'ROLLBACK' )
		@conn.exec( 'LISTEN woo' )
		@conn.exec( 'LISTEN war' )
		@conn.exec( 'LISTEN woz' )

		pid = fork do
			begin
				conn = described_class.connect( @conninfo )
				conn.exec( 'NOTIFY woo' )
				conn.exec( 'NOTIFY war' )
				conn.exec( 'NOTIFY woz' )
			ensure
				conn.finish
				exit!
			end
		end

		Process.wait( pid )

		channels = []
		3.times do
			channels << @conn.wait_for_notify( 2 )
		end

		channels.should have( 3 ).members
		channels.should include( 'woo', 'war', 'woz' )

		@conn.exec( 'UNLISTEN woz' )
		@conn.exec( 'UNLISTEN war' )
		@conn.exec( 'UNLISTEN woo' )
	end

	it "returns notifications which are already in the queue before wait_for_notify is called " +
	   "without waiting for the socket to become readable" do
		@conn.exec( 'ROLLBACK' )
		@conn.exec( 'LISTEN woo' )

		pid = fork do
			begin
				conn = described_class.connect( @conninfo )
				conn.exec( 'NOTIFY woo' )
			ensure
				conn.finish
				exit!
			end
		end

		# Wait for the forked child to send the notification
		Process.wait( pid )

		# Cause the notification to buffer, but not be read yet
		@conn.exec( 'SELECT 1' )

		@conn.wait_for_notify( 10 ).should == 'woo'
		@conn.exec( 'UNLISTEN woo' )
	end

	context "under PostgreSQL 9" do

		before( :each ) do
			pending "only works under PostgreSQL 9" if @conn.server_version < 9_00_00
		end

		it "calls the block supplied to wait_for_notify with the notify payload if it accepts " +
		    "any number of arguments" do

			@conn.exec( 'ROLLBACK' )
			@conn.exec( 'LISTEN knees' )

			pid = fork do
				conn = described_class.connect( @conninfo )
				conn.exec( %Q{NOTIFY knees, 'skirt and boots'} )
				conn.finish
				exit!
			end

			Process.wait( pid )

			event, pid, msg = nil
			@conn.wait_for_notify( 10 ) do |*args|
				event, pid, msg = *args
			end
			@conn.exec( 'UNLISTEN knees' )

			event.should == 'knees'
			pid.should be_a_kind_of( Integer )
			msg.should == 'skirt and boots'
		end

		it "accepts nil as the timeout in #wait_for_notify " do
			@conn.exec( 'ROLLBACK' )
			@conn.exec( 'LISTEN knees' )

			pid = fork do
				conn = described_class.connect( @conninfo )
				conn.exec( %Q{NOTIFY knees} )
				conn.finish
				exit!
			end

			Process.wait( pid )

			event, pid = nil
			@conn.wait_for_notify( nil ) do |*args|
				event, pid = *args
			end
			@conn.exec( 'UNLISTEN knees' )

			event.should == 'knees'
			pid.should be_a_kind_of( Integer )
		end

		it "sends nil as the payload if the notification wasn't given one" do
			@conn.exec( 'ROLLBACK' )
			@conn.exec( 'LISTEN knees' )

			pid = fork do
				conn = described_class.connect( @conninfo )
				conn.exec( %Q{NOTIFY knees} )
				conn.finish
				exit!
			end

			Process.wait( pid )

			payload = :notnil
			@conn.wait_for_notify( nil ) do |*args|
				payload = args[ 2 ]
			end
			@conn.exec( 'UNLISTEN knees' )

			payload.should be_nil()
		end

		it "calls the block supplied to wait_for_notify with the notify payload if it accepts " +
		   "two arguments" do

			@conn.exec( 'ROLLBACK' )
			@conn.exec( 'LISTEN knees' )

			pid = fork do
				conn = described_class.connect( @conninfo )
				conn.exec( %Q{NOTIFY knees, 'skirt and boots'} )
				conn.finish
				exit!
			end

			Process.wait( pid )

			event, pid, msg = nil
			@conn.wait_for_notify( 10 ) do |arg1, arg2|
				event, pid, msg = arg1, arg2
			end
			@conn.exec( 'UNLISTEN knees' )

			event.should == 'knees'
			pid.should be_a_kind_of( Integer )
			msg.should be_nil()
		end

		it "calls the block supplied to wait_for_notify with the notify payload if it " +
		   "doesn't accept arguments" do

			@conn.exec( 'ROLLBACK' )
			@conn.exec( 'LISTEN knees' )

			pid = fork do
				conn = described_class.connect( @conninfo )
				conn.exec( %Q{NOTIFY knees, 'skirt and boots'} )
				conn.finish
				exit!
			end

			Process.wait( pid )

			notification_received = false
			@conn.wait_for_notify( 10 ) do
				notification_received = true
			end
			@conn.exec( 'UNLISTEN knees' )

			notification_received.should be_true()
		end

		it "calls the block supplied to wait_for_notify with the notify payload if it accepts " +
		   "three arguments" do

			@conn.exec( 'ROLLBACK' )
			@conn.exec( 'LISTEN knees' )

			pid = fork do
				conn = described_class.connect( @conninfo )
				conn.exec( %Q{NOTIFY knees, 'skirt and boots'} )
				conn.finish
				exit!
			end

			Process.wait( pid )

			event, pid, msg = nil
			@conn.wait_for_notify( 10 ) do |arg1, arg2, arg3|
				event, pid, msg = arg1, arg2, arg3
			end
			@conn.exec( 'UNLISTEN knees' )

			event.should == 'knees'
			pid.should be_a_kind_of( Integer )
			msg.should == 'skirt and boots'
		end

	end

	it "yields the result if block is given to exec" do
		rval = @conn.exec( "select 1234::int as a union select 5678::int as a" ) do |result|
			values = []
			result.should be_kind_of( PG::Result )
			result.ntuples.should == 2
			result.each do |tuple|
				values << tuple['a']
			end
			values
		end

		rval.should have( 2 ).members
		rval.should include( '5678', '1234' )
	end


	it "correctly finishes COPY queries passed to #async_exec" do
		@conn.async_exec( "COPY (SELECT 1 UNION ALL SELECT 2) TO STDOUT" )

		results = []
		begin
			data = @conn.get_copy_data( true )
			if false == data
				@conn.block( 2.0 )
				data = @conn.get_copy_data( true )
			end
			results << data if data
		end until data.nil?

		results.should have( 2 ).members
		results.should include( "1\n", "2\n" )
	end


	it "described_class#block shouldn't block a second thread" do
		t = Thread.new do
			@conn.send_query( "select pg_sleep(3)" )
			@conn.block
		end

		# :FIXME: There's a race here, but hopefully it's pretty small.
		t.should be_alive()

		@conn.cancel
		t.join
	end

	it "described_class#block should allow a timeout" do
		@conn.send_query( "select pg_sleep(3)" )

		start = Time.now
		@conn.block( 0.1 )
		finish = Time.now

		(finish - start).should be_within( 0.05 ).of( 0.1 )
	end


	it "can encrypt a string given a password and username" do
		described_class.encrypt_password("postgres", "postgres").
			should =~ /\S+/
	end


	it "raises an appropriate error if either of the required arguments for encrypt_password " +
	   "is not valid" do
		expect {
			described_class.encrypt_password( nil, nil )
		}.to raise_error( TypeError )
		expect {
			described_class.encrypt_password( "postgres", nil )
		}.to raise_error( TypeError )
		expect {
			described_class.encrypt_password( nil, "postgres" )
		}.to raise_error( TypeError )
	end


	it "allows fetching a column of values from a result by column number" do
		res = @conn.exec( 'VALUES (1,2),(2,3),(3,4)' )
		res.column_values( 0 ).should == %w[1 2 3]
		res.column_values( 1 ).should == %w[2 3 4]
	end


	it "allows fetching a column of values from a result by field name" do
		res = @conn.exec( 'VALUES (1,2),(2,3),(3,4)' )
		res.field_values( 'column1' ).should == %w[1 2 3]
		res.field_values( 'column2' ).should == %w[2 3 4]
	end


	it "raises an error if selecting an invalid column index" do
		res = @conn.exec( 'VALUES (1,2),(2,3),(3,4)' )
		expect {
			res.column_values( 20 )
		}.to raise_error( IndexError )
	end


	it "raises an error if selecting an invalid field name" do
		res = @conn.exec( 'VALUES (1,2),(2,3),(3,4)' )
		expect {
			res.field_values( 'hUUuurrg' )
		}.to raise_error( IndexError )
	end


	it "raises an error if column index is not a number" do
		res = @conn.exec( 'VALUES (1,2),(2,3),(3,4)' )
		expect {
			res.column_values( 'hUUuurrg' )
		}.to raise_error( TypeError )
	end


	it "can connect asynchronously" do
		serv = TCPServer.new( '127.0.0.1', 54320 )
		conn = described_class.connect_start( '127.0.0.1', 54320, "", "", "me", "xxxx", "somedb" )
		conn.connect_poll.should == PG::PGRES_POLLING_WRITING
		select( nil, [IO.for_fd(conn.socket)], nil, 0.2 )
		serv.close
		if conn.connect_poll == PG::PGRES_POLLING_READING
			select( [IO.for_fd(conn.socket)], nil, nil, 0.2 )
		end
		conn.connect_poll.should == PG::PGRES_POLLING_FAILED
	end

	it "discards previous results (if any) before waiting on an #async_exec"

	it "calls the block if one is provided to #async_exec" do
		result = nil
		@conn.async_exec( "select 47 as one" ) do |pg_res|
			result = pg_res[0]
		end
		result.should == { 'one' => '47' }
	end

	it "raises a rescue-able error if #finish is called twice", :without_transaction do
		conn = PG.connect( @conninfo )

		conn.finish
		expect { conn.finish }.to raise_error( PG::Error, /connection is closed/i )
	end


	describe "multinationalization support", :ruby_19 => true do

		it "should return the same bytes in text format that are sent as inline text" do
			binary_file   = File.join(Dir.pwd, 'spec/data', 'random_binary_data')
			in_bytes      = File.open(binary_file, 'r:ASCII-8BIT').read
			escaped_bytes = described_class.escape_bytea( in_bytes )
			out_bytes     = nil

			@conn.transaction do |conn|
				conn.exec("SET standard_conforming_strings=on")
				res = conn.exec("VALUES ('#{escaped_bytes}'::bytea)", [], 0)
				out_bytes = described_class.unescape_bytea( res[0]['column1'] )
			end

			out_bytes.should == in_bytes
		end

		describe "rubyforge #22925: m17n support" do
			it "should return results in the same encoding as the client (iso-8859-1)" do
				out_string = nil
				@conn.transaction do |conn|
					conn.internal_encoding = 'iso8859-1'
					res = conn.exec("VALUES ('fantasia')", [], 0)
					out_string = res[0]['column1']
				end
				out_string.should == 'fantasia'
				out_string.encoding.should == Encoding::ISO8859_1
			end

			it "should return results in the same encoding as the client (utf-8)" do
				out_string = nil
				@conn.transaction do |conn|
					conn.internal_encoding = 'utf-8'
					res = conn.exec("VALUES ('世界線航跡蔵')", [], 0)
					out_string = res[0]['column1']
				end
				out_string.should == '世界線航跡蔵'
				out_string.encoding.should == Encoding::UTF_8
			end

			it "should return results in the same encoding as the client (EUC-JP)" do
				out_string = nil
				@conn.transaction do |conn|
					conn.internal_encoding = 'EUC-JP'
					stmt = "VALUES ('世界線航跡蔵')".encode('EUC-JP')
					res = conn.exec(stmt, [], 0)
					out_string = res[0]['column1']
				end
				out_string.should == '世界線航跡蔵'.encode('EUC-JP')
				out_string.encoding.should == Encoding::EUC_JP
			end

			it "returns the results in the correct encoding even if the client_encoding has " +
			   "changed since the results were fetched" do
				out_string = nil
				@conn.transaction do |conn|
					conn.internal_encoding = 'EUC-JP'
					stmt = "VALUES ('世界線航跡蔵')".encode('EUC-JP')
					res = conn.exec(stmt, [], 0)
					conn.internal_encoding = 'utf-8'
					out_string = res[0]['column1']
				end
				out_string.should == '世界線航跡蔵'.encode('EUC-JP')
				out_string.encoding.should == Encoding::EUC_JP
			end

			it "the connection should return ASCII-8BIT when it's set to SQL_ASCII" do
				@conn.exec "SET client_encoding TO SQL_ASCII"
				@conn.internal_encoding.should == Encoding::ASCII_8BIT
			end

			it "works around the unsupported JOHAB encoding by returning stuff in 'ASCII_8BIT'" do
				pending "figuring out how to create a string in the JOHAB encoding" do
					out_string = nil
					@conn.transaction do |conn|
						conn.exec( "set client_encoding = 'JOHAB';" )
						stmt = "VALUES ('foo')".encode('JOHAB')
						res = conn.exec( stmt, [], 0 )
						out_string = res[0]['column1']
					end
					out_string.should == 'foo'.encode( Encoding::ASCII_8BIT )
					out_string.encoding.should == Encoding::ASCII_8BIT
				end
			end

			it "uses the client encoding for escaped string" do
				original = "string to escape".force_encoding( "euc-jp" )
				@conn.set_client_encoding( "euc_jp" )
				escaped  = @conn.escape( original )
				escaped.encoding.should == Encoding::EUC_JP
			end
		end


		describe "Ruby 1.9.x default_internal encoding" do

			it "honors the Encoding.default_internal if it's set and the synchronous interface is used" do
				@conn.transaction do |txn_conn|
					txn_conn.internal_encoding = Encoding::ISO8859_1
					txn_conn.exec( "CREATE TABLE defaultinternaltest ( foo text )" )
					txn_conn.exec( "INSERT INTO defaultinternaltest VALUES ('Grün und Weiß')" )
				end

				begin
					prev_encoding = Encoding.default_internal
					Encoding.default_internal = Encoding::UTF_8

					conn = PG.connect( @conninfo )
					conn.internal_encoding.should == Encoding::UTF_8
					res = conn.exec( "SELECT foo FROM defaultinternaltest" )
					res[0]['foo'].encoding.should == Encoding::UTF_8
				ensure
					conn.finish if conn
					Encoding.default_internal = prev_encoding
				end
			end

		end


		it "encodes exception messages with the connection's encoding (#96)", :without_transaction do
			# Use a new connection so the client_encoding isn't set outside of this example
			conn = PG.connect( @conninfo )
			conn.client_encoding = 'iso-8859-15'

			conn.transaction do
				conn.exec "CREATE TABLE foo (bar TEXT)"

				begin
					query = "INSERT INTO foo VALUES ('Côte d'Ivoire')".encode( 'iso-8859-15' )
					conn.exec( query )
				rescue => err
					err.message.encoding.should == Encoding::ISO8859_15
				else
					fail "No exception raised?!"
				end
			end

			conn.finish if conn
		end

	end
end
