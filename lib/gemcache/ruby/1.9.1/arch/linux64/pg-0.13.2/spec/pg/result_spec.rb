#!/usr/bin/env rspec
# encoding: utf-8

BEGIN {
	require 'pathname'

	basedir = Pathname( __FILE__ ).dirname.parent.parent
	libdir = basedir + 'lib'

	$LOAD_PATH.unshift( basedir.to_s ) unless $LOAD_PATH.include?( basedir.to_s )
	$LOAD_PATH.unshift( libdir.to_s ) unless $LOAD_PATH.include?( libdir.to_s )
}

require 'rspec'
require 'spec/lib/helpers'
require 'pg'

describe PG::Result do

	before( :all ) do
		@conn = setup_testing_db( "PG_Result" )
	end

	before( :each ) do
		@conn.exec( 'BEGIN' )
	end

	after( :each ) do
		@conn.exec( 'ROLLBACK' )
	end

	after( :all ) do
		teardown_testing_db( @conn )
	end


	#
	# Examples
	#

	it "should act as an array of hashes" do
		res = @conn.exec("SELECT 1 AS a, 2 AS b")
		res[0]['a'].should== '1'
		res[0]['b'].should== '2'
	end

	it "should insert nil AS NULL and return NULL as nil" do
		res = @conn.exec("SELECT $1::int AS n", [nil])
		res[0]['n'].should be_nil()
	end

	it "encapsulates errors in a PGError object" do
		exception = nil
		begin
			@conn.exec( "SELECT * FROM nonexistant_table" )
		rescue PGError => err
			exception = err
		end

		result = exception.result

		result.should be_a( described_class() )
		result.error_field( PG::PG_DIAG_SEVERITY ).should == 'ERROR'
		result.error_field( PG::PG_DIAG_SQLSTATE ).should == '42P01'
		result.error_field( PG::PG_DIAG_MESSAGE_PRIMARY ).
			should == 'relation "nonexistant_table" does not exist'
		result.error_field( PG::PG_DIAG_MESSAGE_DETAIL ).should be_nil()
		result.error_field( PG::PG_DIAG_MESSAGE_HINT ).should be_nil()
		result.error_field( PG::PG_DIAG_STATEMENT_POSITION ).should == '15'
		result.error_field( PG::PG_DIAG_INTERNAL_POSITION ).should be_nil()
		result.error_field( PG::PG_DIAG_INTERNAL_QUERY ).should be_nil()
		result.error_field( PG::PG_DIAG_CONTEXT ).should be_nil()
		result.error_field( PG::PG_DIAG_SOURCE_FILE ).should =~ /parse_relation\.c$/
		result.error_field( PG::PG_DIAG_SOURCE_LINE ).should == '857'
		result.error_field( PG::PG_DIAG_SOURCE_FUNCTION ).should == 'parserOpenTable'

	end

	it "should detect division by zero as SQLSTATE 22012" do
		sqlstate = nil
		begin
			res = @conn.exec("SELECT 1/0")
		rescue PGError => e
			sqlstate = e.result.result_error_field( PG::PG_DIAG_SQLSTATE ).to_i
		end
		sqlstate.should == 22012
	end

	it "should return the same bytes in binary format that are sent in binary format" do
		binary_file = File.join(Dir.pwd, 'spec/data', 'random_binary_data')
		bytes = File.open(binary_file, 'rb').read
		res = @conn.exec('VALUES ($1::bytea)', 
			[ { :value => bytes, :format => 1 } ], 1)
		res[0]['column1'].should== bytes
	end

	it "should return the same bytes in binary format that are sent as inline text" do
		binary_file = File.join(Dir.pwd, 'spec/data', 'random_binary_data')
		in_bytes = File.open(binary_file, 'rb').read
		out_bytes = nil
		@conn.exec("SET standard_conforming_strings=on")
		res = @conn.exec("VALUES ('#{PG::Connection.escape_bytea(in_bytes)}'::bytea)", [], 1)
		out_bytes = res[0]['column1']
		out_bytes.should == in_bytes
	end

	it "should return the same bytes in text format that are sent in binary format" do
		binary_file = File.join(Dir.pwd, 'spec/data', 'random_binary_data')
		bytes = File.open(binary_file, 'rb').read
		res = @conn.exec('VALUES ($1::bytea)', 
			[ { :value => bytes, :format => 1 } ])
		PG::Connection.unescape_bytea(res[0]['column1']).should== bytes
	end

	it "should return the same bytes in text format that are sent as inline text" do
		binary_file = File.join(Dir.pwd, 'spec/data', 'random_binary_data')
		in_bytes = File.open(binary_file, 'rb').read

		out_bytes = nil
		@conn.exec("SET standard_conforming_strings=on")
		res = @conn.exec("VALUES ('#{PG::Connection.escape_bytea(in_bytes)}'::bytea)", [], 0)
		out_bytes = PG::Connection.unescape_bytea(res[0]['column1'])
		out_bytes.should == in_bytes
	end

	it "should return the parameter type of the specified prepared statment parameter" do
		query = 'SELECT * FROM pg_stat_activity WHERE user = $1::name AND current_query = $2::text'
		@conn.prepare( 'queryfinder', query )
		res = @conn.describe_prepared( 'queryfinder' )

		@conn.exec( 'SELECT format_type($1, -1)', [res.paramtype(0)] ).getvalue( 0, 0 ).
			should == 'name'
		@conn.exec( 'SELECT format_type($1, -1)', [res.paramtype(1)] ).getvalue( 0, 0 ).
			should == 'text'
	end

	it "should raise an exception when a negative index is given to #fformat" do
		res = @conn.exec('SELECT * FROM pg_stat_activity')
		expect {
			res.fformat( -1 )
		}.to raise_error( ArgumentError, /column number/i )
	end

	it "should raise an exception when a negative index is given to #fmod" do
		res = @conn.exec('SELECT * FROM pg_stat_activity')
		expect {
			res.fmod( -1 )
		}.to raise_error( ArgumentError, /column number/i )
	end

	it "should raise an exception when a negative index is given to #[]" do
		res = @conn.exec('SELECT * FROM pg_stat_activity')
		expect {
			res[ -1 ]
		}.to raise_error( IndexError, /-1 is out of range/i )
	end

	it "should raise allow for conversion to an array of arrays" do
		@conn.exec( 'CREATE TABLE valuestest ( foo varchar(33) )' )
		@conn.exec( 'INSERT INTO valuestest ("foo") values (\'bar\')' )
		@conn.exec( 'INSERT INTO valuestest ("foo") values (\'bar2\')' )

		res = @conn.exec( 'SELECT * FROM valuestest' )
		res.values.should == [ ["bar"], ["bar2"] ]
	end

	# PQfmod
	it "can return the type modifier for a result column" do
		@conn.exec( 'CREATE TABLE fmodtest ( foo varchar(33) )' )
		res = @conn.exec( 'SELECT * FROM fmodtest' )
		res.fmod( 0 ).should == 33 + 4 # Column length + varlena size (4)
	end

	it "should raise an exception when an invalid index is passed to PG::Result#fmod" do
		@conn.exec( 'CREATE TABLE fmodtest ( foo varchar(33) )' )
		res = @conn.exec( 'SELECT * FROM fmodtest' )
		expect { res.fmod(1) }.to raise_error( ArgumentError )
	end

	it "should raise an exception when an invalid (negative) index is passed to PG::Result#fmod" do
		@conn.exec( 'CREATE TABLE fmodtest ( foo varchar(33) )' )
		res = @conn.exec( 'SELECT * FROM fmodtest' )
		expect { res.fmod(-11) }.to raise_error( ArgumentError )
	end

	it "shouldn't raise an exception when a valid index is passed to PG::Result#fmod for a column with no typemod" do
		@conn.exec( 'CREATE TABLE fmodtest ( foo text )' )
		res = @conn.exec( 'SELECT * FROM fmodtest' )
		res.fmod( 0 ).should == -1 # and it shouldn't raise an exception, either
	end

	# PQftable
	it "can return the oid of the table from which a result column was fetched" do
		@conn.exec( 'CREATE TABLE ftabletest ( foo text )' )
		res = @conn.exec( 'SELECT * FROM ftabletest' )

		res.ftable( 0 ).should == be_nonzero()
	end

	it "should raise an exception when an invalid index is passed to PG::Result#ftable" do
		@conn.exec( 'CREATE TABLE ftabletest ( foo text )' )
		res = @conn.exec( 'SELECT * FROM ftabletest' )

		expect { res.ftable(18) }.to raise_error( ArgumentError )
	end

	it "should raise an exception when an invalid (negative) index is passed to PG::Result#ftable" do
		@conn.exec( 'CREATE TABLE ftabletest ( foo text )' )
		res = @conn.exec( 'SELECT * FROM ftabletest' )

		expect { res.ftable(-2) }.to raise_error( ArgumentError )
	end

	it "shouldn't raise an exception when a valid index is passed to PG::Result#ftable for a " +
	   "column with no corresponding table" do
		@conn.exec( 'CREATE TABLE ftabletest ( foo text )' )
		res = @conn.exec( 'SELECT foo, LENGTH(foo) as length FROM ftabletest' )
		res.ftable( 1 ).should == PG::INVALID_OID # and it shouldn't raise an exception, either
	end

	# PQftablecol
	it "can return the column number (within its table) of a column in a result" do
		@conn.exec( 'CREATE TABLE ftablecoltest ( foo text, bar numeric )' )
		res = @conn.exec( 'SELECT * FROM ftablecoltest' )

		res.ftablecol( 0 ).should == 1
		res.ftablecol( 1 ).should == 2
	end

	it "should raise an exception when an invalid index is passed to PG::Result#ftablecol" do
		@conn.exec( 'CREATE TABLE ftablecoltest ( foo text, bar numeric )' )
		res = @conn.exec( 'SELECT * FROM ftablecoltest' )

		expect { res.ftablecol(32) }.to raise_error( ArgumentError )
	end

	it "should raise an exception when an invalid (negative) index is passed to PG::Result#ftablecol" do
		@conn.exec( 'CREATE TABLE ftablecoltest ( foo text, bar numeric )' )
		res = @conn.exec( 'SELECT * FROM ftablecoltest' )

		expect { res.ftablecol(-1) }.to raise_error( ArgumentError )
	end

	it "shouldn't raise an exception when a valid index is passed to PG::Result#ftablecol for a " +
	   "column with no corresponding table" do
		@conn.exec( 'CREATE TABLE ftablecoltest ( foo text )' )
		res = @conn.exec( 'SELECT foo, LENGTH(foo) as length FROM ftablecoltest' )
		res.ftablecol(1).should == 0 # and it shouldn't raise an exception, either
	end

end
