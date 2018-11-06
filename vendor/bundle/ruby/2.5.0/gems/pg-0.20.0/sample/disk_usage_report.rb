#!/usr/bin/env ruby
# vim: set noet nosta sw=4 ts=4 :
#
# Quickly dump size information for a given database.
# Top twenty objects, and size per schema.
#
# Mahlon E. Smith <mahlon@martini.nu>
#
# Based on work by Jeff Davis <ruby@j-davis.com>.
#


begin
	require 'ostruct'
	require 'optparse'
	require 'etc'
	require 'pg'

rescue LoadError # 1.8 support
	unless Object.const_defined?( :Gem )
		require 'rubygems'
		retry
	end
	raise
end

SCRIPT_VERSION = %q$Id: disk_usage_report.rb,v 76ebae01c937 2013/03/26 17:50:02 ged $


### Gather data and output it to $stdout.
###
def report( opts )
	db = PG.connect(
		:dbname   => opts.database,
		:host     => opts.host,
		:port     => opts.port,
		:user     => opts.user,
		:password => opts.pass,
		:sslmode  => 'prefer'
	)

	# -----------------------------------------

	db_info = db.exec %Q{
		SELECT
			count(oid) AS num_relations,
			pg_size_pretty(pg_database_size('#{opts.database}')) AS dbsize
		FROM
			pg_class
	}

	puts '=' * 70
	puts "Disk usage information for %s: (%d relations, %s total)" % [
		opts.database,
		db_info[0]['num_relations'],
		db_info[0]['dbsize']
	]
	puts '=' * 70

	# -----------------------------------------

	top_twenty = db.exec %q{
		SELECT
			relname AS name,
			relkind AS kind,
			pg_size_pretty(pg_relation_size(pg_class.oid)) AS size
		FROM
			pg_class
		ORDER BY
			pg_relation_size(pg_class.oid) DESC
		LIMIT 20
	}

	puts 'Top twenty objects by size:'
	puts '-' * 70
	top_twenty.each do |row|
		type = case row['kind']
			   when 'i'; 'index'
			   when 't'; 'toast'
			   when 'r'; 'table'
			   when 'S'; 'sequence'
			   else;     '???'
			   end

		puts "%40s %10s (%s)" % [ row['name'], row['size'], type ]
	end
	puts '-' * 70

	# -----------------------------------------

	schema_sizes = db.exec %q{
		SELECT
			table_schema,
			pg_size_pretty( CAST( SUM(pg_total_relation_size(table_schema || '.' || table_name)) AS bigint)) AS size
		FROM
			information_schema.tables
		GROUP BY
			table_schema
		ORDER BY
			CAST( SUM(pg_total_relation_size(table_schema || '.' || table_name)) AS bigint ) DESC
	}


	puts 'Size per schema:'
	puts '-' * 70
	schema_sizes.each do |row|
		puts "%20s %10s" % [ row['table_schema'], row['size'] ]
	end
	puts '-' * 70
	puts

	db.finish
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
	options.interval = 5

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

		opts.on_tail( '--help', 'show this help, then exit' ) do
			$stderr.puts opts
			exit
		end

		opts.on_tail( '--version', 'output version information, then exit' ) do
			puts SCRIPT_VERSION
			exit
		end
	end

	opts.parse!( args )
	return options
end


if __FILE__ == $0
	opts = parse_args( ARGV )
	report( opts )
end

