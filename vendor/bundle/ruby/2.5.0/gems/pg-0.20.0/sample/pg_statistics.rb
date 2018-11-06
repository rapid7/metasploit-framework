#!/usr/bin/env ruby
# vim: set noet nosta sw=4 ts=4 :
#
# PostgreSQL statistic gatherer.
# Mahlon E. Smith <mahlon@martini.nu>
#
# Based on queries by Kenny Gorman.
#     http://www.kennygorman.com/wordpress/?page_id=491
#
# An example gnuplot input script is included in the __END__ block
# of this script.  Using it, you can feed the output this script
# generates to gnuplot (after removing header lines) to generate
# some nice performance charts.
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


### PostgreSQL Stats.  Fetch information from pg_stat_* tables.
### Optionally run in a continuous loop, displaying deltas.
###
class Stats
	VERSION = %q$Id: pg_statistics.rb,v 36ca5b412583 2012/04/17 23:32:25 mahlon $

	def initialize( opts )
		@opts = opts
		@db   = PG.connect(
			:dbname   => opts.database,
			:host     => opts.host,
			:port     => opts.port,
			:user     => opts.user,
			:password => opts.pass,
			:sslmode  => 'prefer'
		)
		@last = nil
	end

	######
	public
	######

	### Primary loop.  Gather statistics and generate deltas.
	###
	def run
		run_count = 0

		loop do
			current_stat = self.get_stats

			# First run, store and continue
			#
			if @last.nil?
				@last = current_stat
				sleep @opts.interval
				next
			end

			# headers
			#
			if run_count == 0 || run_count % 50 == 0
				puts "%-20s%12s%12s%12s%12s%12s%12s%12s%12s%12s%12s%12s%12s%12s%12s" % %w[
					time commits rollbks blksrd blkshit bkends seqscan
					seqtprd idxscn idxtrd ins upd del locks activeq
				]
			end

			# calculate deltas
			#
			delta = current_stat.inject({}) do |h, pair|
				stat, val = *pair

				if %w[ activeq locks bkends ].include?( stat )
					h[stat] = current_stat[stat].to_i
				else
					h[stat] = current_stat[stat].to_i - @last[stat].to_i
				end

				h
			end
			delta[ 'time' ] = Time.now.strftime('%F %T')

			# new values
			#
			puts "%-20s%12s%12s%12s%12s%12s%12s%12s%12s%12s%12s%12s%12s%12s%12s" % [
				delta['time'], delta['commits'], delta['rollbks'], delta['blksrd'],
				delta['blkshit'], delta['bkends'], delta['seqscan'],
				delta['seqtprd'], delta['idxscn'], delta['idxtrd'],
				delta['ins'], delta['upd'], delta['del'], delta['locks'], delta['activeq']
			]

			@last = current_stat
			run_count += 1
			sleep @opts.interval
		end
	end


	### Query the database for performance measurements.  Returns a hash.
	###
	def get_stats
		res = @db.exec %Q{
			SELECT
				MAX(stat_db.xact_commit)       AS commits,
				MAX(stat_db.xact_rollback)     AS rollbks,
				MAX(stat_db.blks_read)         AS blksrd,
				MAX(stat_db.blks_hit)          AS blkshit,
				MAX(stat_db.numbackends)       AS bkends,
				SUM(stat_tables.seq_scan)      AS seqscan,
				SUM(stat_tables.seq_tup_read)  AS seqtprd,
				SUM(stat_tables.idx_scan)      AS idxscn,
				SUM(stat_tables.idx_tup_fetch) AS idxtrd,
				SUM(stat_tables.n_tup_ins)     AS ins,
				SUM(stat_tables.n_tup_upd)     AS upd,
				SUM(stat_tables.n_tup_del)     AS del,
				MAX(stat_locks.locks)          AS locks,
				MAX(activity.sess)             AS activeq
			FROM
				pg_stat_database    AS stat_db,
				pg_stat_user_tables AS stat_tables,
				(SELECT COUNT(*) AS locks FROM pg_locks ) AS stat_locks,
				(SELECT COUNT(*) AS sess FROM pg_stat_activity WHERE current_query <> '<IDLE>') AS activity
			WHERE
				stat_db.datname = '%s';
		} % [ @opts.database ]

		return res[0]
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
	options.sslmode  = 'disable'
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

		opts.on( '-i', '--interval SECONDS', Integer,
				 "refresh interval in seconds (default: \"#{options.interval}\")") do |seconds|
			options.interval = seconds
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


### Go!
###
if __FILE__ == $0
	$stdout.sync = true
	Stats.new( parse_args( ARGV ) ).run
end


__END__
######################################################################
### T E R M I N A L   O P T I O N S
######################################################################

#set terminal png nocrop enhanced font arial 8 size '800x600' x000000 xffffff x444444
#set output 'graph.png'

set terminal pdf linewidth 4 size 11,8
set output 'graph.pdf'

#set terminal aqua


######################################################################
### O P T I O N S   F O R   A L L   G R A P H S
######################################################################

set multiplot layout 2,1 title "PostgreSQL Statistics\n5 second sample rate (smoothed)"

set grid x y
set key right vertical outside
set key nobox
set xdata time
set timefmt "%Y-%m-%d.%H:%M:%S"
set format x "%l%p"
set xtic rotate by -45
input_file = "database_stats.txt"

# edit to taste!
set xrange ["2012-04-16.00:00:00":"2012-04-17.00:00:00"]


######################################################################
### G R A P H   1
######################################################################

set title "Database Operations and Connection Totals"
set yrange [0:200]

plot \
    input_file using 1:2 title "Commits" with lines smooth bezier, \
    input_file using 1:3 title "Rollbacks" with lines smooth bezier, \
    input_file using 1:11 title "Inserts" with lines smooth bezier, \
    input_file using 1:12 title "Updates" with lines smooth bezier, \
    input_file using 1:13 title "Deletes" with lines smooth bezier, \
    input_file using 1:6 title "Backends (total)" with lines, \
    input_file using 1:15 title "Active queries (total)" with lines smooth bezier


######################################################################
### G R A P H   2
######################################################################

set title "Backend Performance"
set yrange [0:10000]

plot \
    input_file using 1:4 title "Block (cache) reads" with lines smooth bezier, \
    input_file using 1:5 title "Block (cache) hits" with lines smooth bezier, \
    input_file using 1:7 title "Sequence scans" with lines smooth bezier, \
    input_file using 1:8 title "Sequence tuple reads" with lines smooth bezier, \
    input_file using 1:9 title "Index scans" with lines smooth bezier, \
    input_file using 1:10 title "Index tuple reads" with lines smooth bezier


######################################################################
### C L E A N U P
######################################################################

unset multiplot
reset

