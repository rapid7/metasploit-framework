#!/usr/bin/env ruby
# vim: set noet nosta sw=4 ts=4 :
#
# Get the current WAL segment and offset from a master postgresql
# server, and compare slave servers to see how far behind they
# are in MB.  This script should be easily modified for use with
# Nagios/Mon/Monit/Zabbix/whatever, or wrapping it in a display loop,
# and is suitable for both WAL shipping or streaming forms of replication.
#
# Mahlon E. Smith <mahlon@martini.nu>
#
# First argument is the master server, all other arguments are treated
# as slave machines.
#
#	db_replication.monitor db-master.example.com ...
#

begin
	require 'ostruct'
	require 'optparse'
	require 'pathname'
	require 'etc'
	require 'pg'
	require 'pp'

rescue LoadError # 1.8 support
	unless Object.const_defined?( :Gem )
		require 'rubygems'
		retry
	end
	raise
end


### A class to encapsulate the PG handles.
###
class PGMonitor

	VERSION = %q$Id: replication_monitor.rb,v 36ca5b412583 2012/04/17 23:32:25 mahlon $

	# When to consider a slave as 'behind', measured in WAL segments.
	# The default WAL segment size is 16, so we'll alert after
	# missing two WAL files worth of data.
	#
	LAG_ALERT = 32

	### Create a new PGMonitor object.
	###
	def initialize( opts, hosts )
		@opts        = opts
		@master      = hosts.shift
		@slaves      = hosts
		@current_wal = {}
		@failures    = []
	end

	attr_reader :opts, :current_wal, :master, :slaves, :failures


	### Perform the connections and check the lag.
	###
	def check
		# clear prior failures, get current xlog info
		@failures = []
		return unless self.get_current_wal

		# check all slaves
		self.slaves.each do |slave|
			begin
				slave_db = PG.connect(
					:dbname   => self.opts.database,
					:host     => slave,
					:port     => self.opts.port,
					:user     => self.opts.user,
					:password => self.opts.pass,
					:sslmode  => 'prefer'
				)

				xlog = slave_db.exec( 'SELECT pg_last_xlog_receive_location()' ).getvalue( 0, 0 )
				slave_db.close

				lag_in_megs = ( self.find_lag( xlog ).to_f / 1024 / 1024 ).abs
				if lag_in_megs >= LAG_ALERT
					failures << { :host => slave,
						:error => "%0.2fMB behind the master." % [ lag_in_megs ] }
				end
			rescue => err
				failures << { :host => slave, :error => err.message }
			end
		end
	end


	#########
	protected
	#########

	### Ask the master for the current xlog information, to compare
	### to slaves.  Returns true on succcess.  On failure, populates
	### the failures array and returns false.
	###
	def get_current_wal
		master_db = PG.connect(
			:dbname   => self.opts.database,
			:host     => self.master,
			:port     => self.opts.port,
			:user     => self.opts.user,
			:password => self.opts.pass,
			:sslmode  => 'prefer'
		)

		self.current_wal[ :segbytes ] = master_db.exec( 'SHOW wal_segment_size' ).
			getvalue( 0, 0 ).sub( /\D+/, '' ).to_i << 20

		current = master_db.exec( 'SELECT pg_current_xlog_location()' ).getvalue( 0, 0 )
		self.current_wal[ :segment ], self.current_wal[ :offset ] = current.split( /\// )

		master_db.close
		return true

	# If we can't get any of the info from the master, then there is no
	# point in a comparison with slaves.
	#
	rescue => err
		self.failures << { :host => self.master,
			:error => 'Unable to retrieve required info from the master (%s)' % [ err.message ] }

		return false
	end


	### Given an +xlog+ position from a slave server, return
	### the number of bytes the slave needs to replay before it
	### is caught up to the master.
	###
	def find_lag( xlog )
		s_segment, s_offset = xlog.split( /\// )
		m_segment  = self.current_wal[ :segment ]
		m_offset   = self.current_wal[ :offset ]
		m_segbytes = self.current_wal[ :segbytes ]

		return (( m_segment.hex - s_segment.hex ) * m_segbytes) + ( m_offset.hex - s_offset.hex )
	end

end


### Parse command line arguments.  Return a struct of global options.
###
def parse_args( args )
	options          = OpenStruct.new
	options.database = 'postgres'
	options.port     = 5432
	options.user     = Etc.getpwuid( Process.uid ).name
	options.sslmode  = 'prefer'

	opts = OptionParser.new do |opts|
		opts.banner = "Usage: #{$0} [options] <master> <slave> [slave2, slave3...]"

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
				options.pass = $stdin.gets.chomp
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
			puts PGMonitor::VERSION
			exit
		end
	end

	opts.parse!( args )
	return options
end



if __FILE__ == $0
	opts = parse_args( ARGV )
	raise ArgumentError, "At least two PostgreSQL servers are required." if ARGV.length < 2
	mon = PGMonitor.new( opts, ARGV )

	mon.check
	if mon.failures.empty?
		puts "All is well!"
		exit 0
	else
		puts "Database replication delayed or broken."
		mon.failures.each do |bad|
			puts "%s: %s" % [ bad[ :host ], bad[ :error ] ]
		end
		exit 1
	end
end


