#!/usr/bin/env ruby
#
# A script to wrap ssh and rsync for PostgreSQL WAL files shipping.
# Mahlon E. Smith <mahlon@martini.nu>
#
# Based off of Joshua Drake's PITRTools concept, but with some important
# differences:
#
#	- Only supports PostgreSQL >= 8.3
#	- No support for rsync version < 3
#	- Only shipping, no client side sync (too much opportunity for failure,
#	  and it's easy to get a base backup manually)
#	- WAL files are only stored once, regardless of how many
#	  slaves are configured or not responding, and are removed from
#	  the master when they are no longer needed.
#	- Each slave can have completely distinct settings, instead
#	  of a single set of options applied to all slaves
#	- slave sync can be individually paused from the master
#	- can run synchronously, or if you have a lot of slaves, threaded async mode
#	- It's ruby, instead of python.  :)
#
# wal_shipper is configurable via an external YAML file, and will create
# a template on its first run -- you'll need to modify it!  It expects
# a directory structure like so:
#
#	postgres/
#		data/...
#		bin/wal_shipper.rb
#		etc/wal_shipper.conf   <-- YAML settings!
#		wal/
#
# It should be loaded from the PostgreSQL master's postgresql.conf
# as such, after putting it into your postgres user homedir under 'bin':
#
#	archive_command = '/path/to/postgres_home/bin/wal_shipper.rb %p'
#
# Passwordless ssh keys need to be set up for the postgres user on all
# participating masters and slaves.
#
# You can use any replay method of your choosing on the slaves.
# Here's a nice example using pg_standby, to be put in data/recovery.conf:
#
#	restore_command = 'pg_standby -t /tmp/pgrecovery.done -s5 -w0 -c /path/to/postgres_home/wal_files/ %f %p %r'
#
# Or, here's another simple alternative data/recovery.conf, for using WAL shipping
# alongside streaming replication:
#
#    standby_mode = 'on'
#    primary_conninfo = 'host=master.example.com port=5432 user=repl password=XXXXXXX'
#    restore_command = 'cp /usr/local/pgsql/wal/%f %p'
#    trigger_file = '/usr/local/pgsql/pg.become_primary'
#    archive_cleanup_command = '/usr/local/bin/pg_archivecleanup /usr/local/pgsql/wal %r'
#
#========================================================================================


require 'pathname'
require 'yaml'
require 'fileutils'
require 'ostruct'


### Encapsulate WAL shipping functionality.
###
module WalShipper

	### Send messages to the PostgreSQL log files.
	###
	def log( msg )
		return unless @debug
		puts "WAL Shipper: %s" % [ msg ]
	end


	### An object that represents a single destination from the
	### configuration file.
	###
	class Destination < OpenStruct
		include WalShipper

		### Create a new WalShipper::Destination object.
		def initialize( dest, debug=false )
			@debug = debug
			super( dest )
			self.validate
		end

		#########
		protected
		#########


		### Check for required keys and normalize various keys.
		###
		def validate
			# Check for required destination keys
			%w[ label kind ].each do |key|
				if self.send( key.to_sym ).nil?
					self.log "Destination %p missing required '%s' key." % [ self, key ]
					self.invalid = true
				end
			end

			# Ensure paths are Pathnames for the 'file' destination type.
			self.path = Pathname.new( self.path ) if self.kind == 'file'

			if self.kind == 'rsync-ssh'
				self.port ||= 22
				self.user = self.user ? "#{self.user}@" : ''
			end
		end
	end # Class Destination



	### Class for creating new Destination objects and determining how to
	### ship WAL files to them.
	###
	class Dispatcher
		include WalShipper

		### Create a new Shipper object, given a +conf+ hash and a +wal+ file
		### Pathname object.
		###
		def initialize( wal, conf )
			# Make the config keys instance variables.
			conf.each_pair {|key, val| self.instance_variable_set( "@#{key}", val ) }

			# Spool directory check.
			#
			@spool = Pathname.new( @spool )
			@spool.exist? or raise "The configured spool directory (%s) doesn't exist." % [ @spool ]

			# Stop right away if we have disabled shipping.
			#
			unless @enabled
				self.log "WAL shipping is disabled, queuing segment %s" % [ wal.basename ]
				exit 1
			end

			# Instantiate Destination objects, creating new spool directories
			# for each.
			#
			@destinations.
				collect!{|dest| WalShipper::Destination.new( dest, @debug ) }.
				reject  {|dest| dest.invalid }.
				collect do |dest|
					dest.spool = @spool + dest.label
					dest.spool.mkdir( 0711 ) unless dest.spool.exist?
					dest
				end

			# Put the WAL file into the spool for processing!
			#
			@waldir = @spool + 'wal_segments'
			@waldir.mkdir( 0711 ) unless @waldir.exist?

			self.log "Copying %s to %s" % [ wal.basename, @waldir ]
			FileUtils::cp wal, @waldir

			# 'wal' now references the copy.  The original is managed and auto-expired
			# by PostgreSQL when a new checkpoint segment it reached.
			@wal = @waldir + wal.basename
		end


		### Create hardlinks for the WAL file into each of the destination directories
		### for separate queueing and recording of what was shipped successfully.
		###
		def link
			@destinations.each do |dest|
				self.log "Linking %s into %s" % [ @wal.basename, dest.spool.basename ]
				FileUtils::ln @wal, dest.spool, :force => true
			end
		end


		### Decide to be synchronous or threaded, and delegate each destination
		### to the proper ship method.
		###
		def dispatch
			# Synchronous mode.
			#
			unless @async
				self.log "Performing a synchronous dispatch."
				@destinations.each {|dest| self.dispatch_dest( dest ) }
				return
			end

			tg = ThreadGroup.new

			# Async, one thread per destination
			#
			if @async_max.nil? || @async_max.to_i.zero?
				self.log "Performing an asynchronous dispatch: one thread per destination."
				@destinations.each do |dest|
					t = Thread.new do
						Thread.current.abort_on_exception = true
						self.dispatch_dest( dest )
					end
					tg.add( t )
				end
				tg.list.each {|t| t.join }
				return
			end

			# Async, one thread per destination, in groups of asynx_max size.
			#
			self.log "Performing an asynchronous dispatch: one thread per destination, %d at a time." % [ @async_max ]
			all_dests = @destinations.dup
			dest_chunks = []
			until all_dests.empty? do
				dest_chunks << all_dests.slice!( 0, @async_max )
			end

			dest_chunks.each do |chunk|
				chunk.each do |dest|
					t = Thread.new do
						Thread.current.abort_on_exception = true
						self.dispatch_dest( dest )
					end
					tg.add( t )
				end

				tg.list.each {|t| t.join }
			end

			return
		end


		### Remove any WAL segments no longer needed by slaves.
		###
		def clean_spool
			total = 0
			@waldir.children.each do |wal|
				if wal.stat.nlink == 1
					total += wal.unlink
				end
			end

			self.log "Removed %d WAL segment%s." % [ total, total == 1 ? '' : 's' ]
		end



		#########
		protected
		#########

		### Send WAL segments to remote +dest+ via rsync+ssh.
		### Passwordless keys between the user running this script (postmaster owner)
		### and remote user need to be set up in advance.
		###
		def ship_rsync_ssh( dest )
			if dest.host.nil?
				self.log "Destination %p missing required 'host' key.  WAL is queued." % [ dest.host ]
				return
			end

			rsync_flags = '-zc'
			ssh_string = "%s -o ConnectTimeout=%d -o StrictHostKeyChecking=no -p %d" %
				[ @ssh, @ssh_timeout || 10, dest.port ]
			src_string = ''
			dst_string = "%s%s:%s/" % [ dest.user, dest.host, dest.path ]

			# If there are numerous files in the spool dir, it means there was
			# an error transferring to this host in the past.  Try and ship all
			# WAL segments, instead of just the new one.  PostgreSQL on the slave
			# side will "do the right thing" as they come in, regardless of
			# ordering.
			#
			if dest.spool.children.length > 1
				src_string = dest.spool.to_s + '/'
				rsync_flags << 'r'
			else
				src_string = dest.spool + @wal.basename
			end


			ship_wal_cmd = [
				@rsync,
				@debug ? (rsync_flags << 'vh') : (rsync_flags << 'q'),
				'--remove-source-files',
				'-e', ssh_string,
				src_string, dst_string
			]

			self.log "Running command '%s'" % [ ship_wal_cmd.join(' ') ]
			system *ship_wal_cmd

			# Run external notification program on error, if one is configured.
			#
			unless $?.success?
				self.log "Ack!  Error while shipping to %p, WAL is queued." % [ dest.label ]
				system @error_cmd, dest.label if @error_cmd
			end
		end


		### Copy WAL segments to remote path as set in +dest+.
		### This is useful for longer term PITR, copying to NFS shares, etc.
		###
		def ship_file( dest )
			if dest.path.nil?
				self.log "Destination %p missing required 'path' key.  WAL is queued." % [ dest ]
				return
			end
			dest.path.mkdir( 0711 ) unless dest.path.exist?

			# If there are numerous files in the spool dir, it means there was
			# an error transferring to this host in the past.  Try and ship all
			# WAL segments, instead of just the new one.  PostgreSQL on the slave
			# side will "do the right thing" as they come in, regardless of
			# ordering.
			#
			if dest.spool.children.length > 1
				dest.spool.children.each do |wal|
					wal.unlink if self.copy_file( wal, dest.path, dest.label, dest.compress )
				end
			else
				wal = dest.spool + @wal.basename
				wal.unlink if self.copy_file( wal, dest.path, dest.label, dest.compress )
			end
		end


		### Given a +wal+ Pathname, a +path+ destination, and the destination
		### label, copy and optionally compress a WAL file.
		###
		def copy_file( wal, path, label, compress=false )
			dest_file = path + wal.basename
			FileUtils::cp wal, dest_file
			if compress
				system *[ 'gzip', '-f', dest_file ]
				raise "Error while compressing: %s" % [ wal.basename ] unless $?.success?
			end
			self.log "Copied %s%s to %s." %
				[ wal.basename, compress ? ' (and compressed)' : '', path ]
			return true
		rescue => err
			self.log "Ack!  Error while copying '%s' (%s) to %p, WAL is queued." %
				[ wal.basename, err.message, path ]
			system @error_cmd, label if @error_cmd
			return false
		end


		### Figure out how to send the WAL file to its intended destination +dest+.
		###
		def dispatch_dest( dest )
			if ! dest.enabled.nil? && ! dest.enabled
				self.log "Skipping explicity disabled destination %p, WAL is queued." % [ dest.label ]
				return
			end

			# Send to the appropriate method.  ( rsync-ssh --> ship_rsync_ssh )
			#
			meth = ( 'ship_' + dest.kind.gsub(/-/, '_') ).to_sym
			if WalShipper::Dispatcher.method_defined?( meth )
				self.send( meth, dest )
			else
				self.log "Unknown destination kind %p for %p.  WAL is queued." % [ dest.kind, dest.label ]
			end
		end
	end
end

# Ship the WAL file!
#
if __FILE__ == $0
	CONFIG_DIR = Pathname.new( __FILE__ ).dirname.parent + 'etc'
	CONFIG     = CONFIG_DIR + 'wal_shipper.conf'

	unless CONFIG.exist?
		CONFIG_DIR.mkdir( 0711 ) unless CONFIG_DIR.exist?
		CONFIG.open('w') {|conf| conf.print(DATA.read) }
		CONFIG.chmod( 0644 )
		puts "No WAL shipping configuration found, default file created."
	end

	wal  = ARGV[0] or raise "No WAL file was specified on the command line."
	wal  = Pathname.new( wal )
	conf = YAML.load( CONFIG.read )

	shipper = WalShipper::Dispatcher.new( wal, conf )
	shipper.link
	shipper.dispatch
	shipper.clean_spool
end


__END__
---
# Spool from pg_xlog to the working area?
# This must be set to 'true' for wal shipping to function!
enabled: false

# Log everything to the PostgreSQL log files?
debug: true

# The working area for WAL segments.
spool: /opt/local/var/db/postgresql84/wal

# With multiple slaves, ship WAL in parallel, or be synchronous?
async: false

# Put a ceiling on the parallel threads?
# '0' or removing this option uses a thread for each destination,
# regardless of how many you have.  Keep in mind that's 16 * destination
# count megs of simultaneous bandwidth.
async_max: 5

# Paths and settings for various binaries.
rsync: /usr/bin/rsync
ssh: /usr/bin/ssh
ssh_timeout: 10

destinations:

- label: rsync-example
  port: 2222
  kind: rsync-ssh
  host: localhost
  user: postgres
  path: wal    # relative to the user's homedir on the remote host
  enabled: false

- label: file-example
  kind: file
  compress: true
  enabled: true
  path: /tmp/someplace

