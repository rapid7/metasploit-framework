##
# $Id$
##

class Metasploit3 < Msf::Auxiliary

	include Exploit::Remote::HttpClient
	include Exploit::Remote::HttpServer

	def initialize
		super(
			'Name'        => 'HTTP Connect Proxy',
			'Version'     => '$Revision$',
			'Description' => %q{
				This module creates an HTTP proxy using Rex' HTTP modules.
				SSL is supported and requests follow the switchboard through
				configured upstream proxies and pivots. This version directs
				all http traffic to a specific host and port such as an upstream
				analysis proxy or a server within an isolated network.
			},
			'Author'      => 'RageLtMan',
			'License'     => MSF_LICENSE
		)

		deregister_options( 'URI', 'URIPATH')

		register_options(
			[
				OptPort.new('SRVPORT', [ true, "Listener port", 80 ]),
				OptAddress.new('SRVHOST', [ true, "Listener socket address", "0.0.0.0" ]),
			], self.class)


		# Accept all URI and vHOSTS
		datastore['URIPATH'] = '/'
		# Chunked transfer
		datastore['HTTP::chunked'] = true
	end


	def run
		start_service
		loop do
			# Wait for termination
			Rex::ThreadSafe.sleep(2)
		end
	end
	alias_method :exploit, :run

	def on_request_uri(cli, req)
		vprint_good("Client #{cli.peerinfo} connected")
		vprint_good(req.to_s)

		# Rewrite or target host
		headers = req.headers.dup
		headers['Host'] = "#{datastore['RHOST']}:#{datastore['RPORT']}"

		# Setup the request headers
		headers['Method'] = req.method
		headers['Uri'] = req.uri
		headers['Vhost'] = req.headers['Host']
		print_error headers.to_s

		# Get response 
		begin 
			res = send_request_raw(headers)
		rescue ::Rex::ConnectionError
			print_error "No response"
		end
		send_response(cli, res.body, res.headers)
	end

end

