module Msf
module Ui
module Web

###
#
# This module takes a web request and processes it.
#
###
module RequestDispatcher

	#
	# Dispatch the supplied request.
	#
	def dispatch_request(cli, req)
		qstring = req.qstring || {}

		dlog("#{cli.peerhost}: Processing request cat=#{qstring['cat']} m=#{qstring['m']}.",
			LogSource)

		case qstring['cat']
			when "e" # exploits
				dispatch_exploit_req(cli, req, qstring)
			when "p" # payloads
				dispatch_payload_req(cli, req, qstring)
			when "s" # sessions
				dispatch_session_req(cli, req, qstring)
		end
	end

	##
	#
	# Exploit-related request dispatching.
	#
	##

	#
	# Dispatch an exploit request based on the particular method that was
	# specified.
	#
	def dispatch_exploit_req(cli, req, qstring)
		case qstring['m']
			when "lst"
				send_exploit_list(cli, req, qstring)	
		end
	end

	#
	# Transmits the exploit list to the client.
	#
	def send_exploit_list(cli, req, qstring)
		body = "<html><table border='1'>"

		framework.exploits.each_module { |name, mod|
			inst = mod.new

			body += "<tr><td>#{name}</td><td>#{inst.name}</td></tr>"
		}

		body += "</table></html>"

		send_ok(cli, body)
	end

	##
	#
	# Payload-related request dispatching.
	#
	##
	
	#
	# Dispatch a payload request based on the particular method that was
	# specified.
	#
	def dispatch_payload_req(cli, req, qstring)
	end

	##
	#
	# Session-related request dispatching.
	#
	##
	
	#
	# Dispatch a session request based on the particular method that was
	# specified.
	#
	def dispatch_session_req(cli, req, qstring)
	end

protected

	#
	# Transmits the supplied body in a 200/OK response to the client.
	#
	def send_ok(cli, body)
		resp = Rex::Proto::Http::Response::OK.new

		resp.body = body

		cli.send_response(resp)
	end

end

end
end
end
