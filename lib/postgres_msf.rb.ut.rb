#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'test/unit'
require 'postgres_msf'

$_POSTGRESQL_TEST_SERVERNAME = 'dbsrv'  # Name or IP, default: dbsrv
$_POSTGRESQL_TEST_SERVERPORT =  5432    # Default: 5432
$_POSTGRESQL_TEST_DATABASE   = 'mydb'   # Default: mydb
$_POSTGRESQL_TEST_USERNAME   = 'scott'  # Default: scott
$_POSTGRESQL_TEST_PASSWORD   = 'tiger'  # Default: tiger

class Msf::Db::PostgresPR::UnitTest < ::Test::Unit::TestCase

	def test_connection
		srv = "tcp://#{$_POSTGRESQL_TEST_SERVERNAME}:#{$_POSTGRESQL_TEST_SERVERPORT}"
		conn = Msf::Db::PostgresPR::Connection.new($_POSTGRESQL_TEST_DATABASE,
			$_POSTGRESQL_TEST_USERNAME,
			$_POSTGRESQL_TEST_PASSWORD,
			srv)
		assert_kind_of Msf::Db::PostgresPR::Connection, conn
		assert_kind_of Rex::Socket::Tcp, conn.conn, "should use Rex sockets for TCP"
		assert_nothing_raised { conn.close }
	end

	# Note that this will drop the "test" table for the named database.
	# This is a destructive act!
	def test_query
		srv = "tcp://#{$_POSTGRESQL_TEST_SERVERNAME}:#{$_POSTGRESQL_TEST_SERVERPORT}"
		conn = Msf::Db::PostgresPR::Connection.new($_POSTGRESQL_TEST_DATABASE,
			$_POSTGRESQL_TEST_USERNAME,
			$_POSTGRESQL_TEST_PASSWORD,
			srv)

		begin
			conn.query("drop table test")
		rescue RuntimeError # Cleanup, it may or may not be there.
		end

		assert_nothing_raised do
			conn.query("CREATE TABLE test (i int, v varchar(5))")
			conn.query(%q{INSERT INTO test VALUES (1, 'foo')})
			conn.query(%q{INSERT INTO test VALUES (2, 'bar')})
		end

		resp = conn.query("select * from test")
		assert_equal(2, resp.rows.size)
		assert_equal(2, resp.fields.size)
		assert_equal("SELECT", resp.cmd_tag)
		assert_nothing_raised { conn.query("drop table test") }

	end

end

