#!/usr/bin/env ruby

require 'pg'

c = PG.connect( dbname: 'test' )

# this one works:
c.exec( "DROP TABLE IF EXISTS foo" )
c.exec( "CREATE TABLE foo (strings character varying[]);" )

# But using a prepared statement works:
c.set_error_verbosity( PG::PQERRORS_VERBOSE )
c.prepare( 'stmt', "INSERT INTO foo VALUES ($1);" )

# This won't work
#c.exec_prepared( 'stmt', ["ARRAY['this','that']"] )

# but this will:
c.exec_prepared( 'stmt', ["{'this','that'}"] )

