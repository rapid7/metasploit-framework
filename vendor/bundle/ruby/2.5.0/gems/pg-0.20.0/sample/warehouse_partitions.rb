#!/usr/bin/env ruby
# vim: set nosta noet ts=4 sw=4:
#
# Script to automatically move partitioned tables and their indexes
# to a separate area on disk.
#
# Mahlon E. Smith <mahlon@martini.nu>
#
# Example use case:
#
#   - You've got a heavy insert table, such as syslog data.
#   - This table has a partitioning trigger (or is manually partitioned)
#     by date, to separate incoming stuff from archival/report stuff.
#   - You have a tablespace on cheap or slower disk (maybe even
#     ZFS compressed, or some such!)
#
# The only assumption this script makes is that your tables are dated, and
# the tablespace they're moving into already exists.
#
# A full example, using the syslog idea from above, where each child
# table is date partitioned by a convention of "syslog_YEAR-WEEKOFYEAR":
#
#    syslog             # <--- parent
#    syslog_2012_06     # <--- inherited
#    syslog_2012_07     # <--- inherited
#    syslog_2012_08     # <--- inherited
#    ...
#
# You'd run this script like so:
#
#    ./warehouse_partitions.rb -F syslog_%Y_%U
#
# Assuming this was week 12 of the year, tables syslog_2012_06 through
# syslog_2012_11 would start sequentially migrating into the tablespace
# called 'warehouse'.
#


begin
	require 'date'
	require 'ostruct'
	require 'optparse'
	require 'pathname'
	require 'etc'
	require 'pg'

rescue LoadError # 1.8 support
	unless Object.const_defined?( :Gem )
		require 'rubygems'
		retry
	end
	raise
end


### A tablespace migration class.
###
class PGWarehouse

	def initialize( opts )
		@opts = opts
		@db = PG.connect(
			:dbname   => opts.database,
			:host     => opts.host,
			:port     => opts.port,
			:user     => opts.user,
			:password => opts.pass,
			:sslmode  => 'prefer'
		)
		@db.exec "SET search_path TO %s" % [ opts.schema ] if opts.schema

		@relations = self.relations
	end

	attr_reader :db

	######
	public
	######

	### Perform the tablespace moves.
	###
	def migrate
		if @relations.empty?
			$stderr.puts 'No tables were found for warehousing.'
			return
		end

		$stderr.puts "Found %d relation%s to move." % [ relations.length, relations.length == 1 ? '' : 's' ]
		@relations.sort_by{|_,v| v[:name] }.each do |_, val|
			$stderr.print "  - Moving table '%s' to '%s'... "  % [
				val[:name], @opts.tablespace
			]

			if @opts.dryrun
				$stderr.puts '(not really)'

			else
				age = self.timer do
					db.exec "ALTER TABLE %s SET TABLESPACE %s;" % [
						val[:name], @opts.tablespace
					]
				end
				puts age
			end

			val[ :indexes ].each do |idx|
				$stderr.print "      - Moving index '%s' to '%s'... "  % [
					idx, @opts.tablespace
				]
				if @opts.dryrun
					$stderr.puts '(not really)'

				else
					age = self.timer do
						db.exec "ALTER INDEX %s SET TABLESPACE %s;" % [
							idx, @opts.tablespace
						]
					end
					puts age
				end
			end
		end
	end


	#########
	protected
	#########

	### Get OIDs and current tablespaces for everything under the
	### specified schema.
	###
	def relations
		return @relations if @relations
		relations = {}

		query =  %q{
			SELECT c.oid AS oid,
				c.relname AS name,
				c.relkind AS kind,
				t.spcname AS tspace
			FROM pg_class AS c
			LEFT JOIN pg_namespace n ON n.oid = c.relnamespace
			LEFT JOIN pg_tablespace t ON t.oid = c.reltablespace
			WHERE c.relkind = 'r' }
		query << "AND n.nspname='#{@opts.schema}'" if @opts.schema

		# Get the relations list, along with each element's current tablespace.
		#
		self.db.exec( query ) do |res|
			res.each do |row|
				relations[ row['oid'] ] = {
					:name       => row['name'],
					:tablespace => row['tspace'],
					:indexes    => [],
					:parent     => nil
				}
			end
		end

		# Add table inheritence information.
		#
		db.exec 'SELECT inhrelid AS oid, inhparent AS parent FROM pg_inherits' do |res|
			res.each do |row|
				relations[ row['oid'] ][ :parent ] = row['parent']
			end
		end

		# Remove tables that don't qualify for warehousing.
		#
		#   - Tables that are not children of a parent
		#   - Tables that are already in the warehouse tablespace
		#   - The currently active child (it's likely being written to!)
		#   - Any table that can't be parsed into the specified format
		#
		relations.reject! do |oid, val|
			begin
				val[:parent].nil? ||
				val[:tablespace] == @opts.tablespace ||
				val[:name] == Time.now.strftime( @opts.format ) ||
				! DateTime.strptime( val[:name], @opts.format )
			rescue ArgumentError
				true
			end
		end

		query = %q{
			SELECT c.oid AS oid,
				i.indexname AS name
			FROM pg_class AS c
			INNER JOIN pg_indexes AS i
				ON i.tablename = c.relname }
		query << "AND i.schemaname='#{@opts.schema}'" if @opts.schema

		# Attach index names to tables.
		#
		db.exec( query ) do |res|
			res.each do |row|
				relations[ row['oid'] ][ :indexes ] << row['name'] if relations[ row['oid'] ]
			end
		end

		return relations
	end


	### Wrap arbitrary commands in a human readable timer.
	###
	def timer
		start = Time.now
		yield
		age = Time.now - start

		diff = age
		secs = diff % 60
		diff = ( diff - secs ) / 60
		mins = diff % 60
		diff = ( diff - mins ) / 60
		hour = diff % 24

		return "%02d:%02d:%02d" % [ hour, mins, secs ]
	end
end


### Parse command line arguments.  Return a struct of global options.
###
def parse_args( args )
	options          = OpenStruct.new
	options.database = Etc.getpwuid( Process.uid ).name
	options.host     = '127.0.0.1'
	options.port     = 5432
	options.user     = Etc.getpwuid( Process.uid ).name
	options.sslmode  = 'prefer'
	options.tablespace = 'warehouse'

	opts = OptionParser.new do |opts|
		opts.banner = "Usage: #{$0} [options]"

		opts.separator ''
		opts.separator 'Connection options:'

		opts.on( '-d', '--database DBNAME',
				"specify the database to connect to (default: \"#{options.database}\")" ) do |db|
			options.database = db
		end

		opts.on( '-h', '--host HOSTNAME', 'database server host' ) do |host|
			options.host = host
		end

		opts.on( '-p', '--port PORT', Integer,
				"database server port (default: \"#{options.port}\")" ) do |port|
			options.port = port
		end

		opts.on( '-n', '--schema SCHEMA', String,
				"operate on the named schema only (default: none)" ) do |schema|
			options.schema = schema
		end

		opts.on( '-T', '--tablespace SPACE', String,
				"move old tables to this tablespace (default: \"#{options.tablespace}\")" ) do |tb|
			options.tablespace = tb
		end

		opts.on( '-F', '--tableformat FORMAT', String,
				"The naming format (strftime) for the inherited tables (default: none)" ) do |format|
			options.format = format
		end

		opts.on( '-U', '--user NAME',
				"database user name (default: \"#{options.user}\")" ) do |user|
			options.user = user
		end

		opts.on( '-W', 'force password prompt' ) do |pw|
			print 'Password: '
			begin
				system 'stty -echo'
				options.pass = gets.chomp
			ensure
				system 'stty echo'
				puts
			end
		end

		opts.separator ''
		opts.separator 'Other options:'

		opts.on_tail( '--dry-run', "don't actually do anything" ) do
			options.dryrun = true
		end

		opts.on_tail( '--help', 'show this help, then exit' ) do
			$stderr.puts opts
			exit
		end

		opts.on_tail( '--version', 'output version information, then exit' ) do
			puts Stats::VERSION
			exit
		end
	end

	opts.parse!( args )
	return options
end


if __FILE__ == $0
	opts = parse_args( ARGV )
	raise ArgumentError, "A naming format (-F) is required." unless opts.format

	$stdout.sync = true
	PGWarehouse.new( opts ).migrate
end


