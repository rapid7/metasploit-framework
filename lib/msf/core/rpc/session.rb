require 'rex'
require 'rex/ui/text/output/buffer'

module Msf
module RPC
class Session < Base

	def list(token)
		authenticate(token)
		res = {}
		@framework.sessions.each do |sess|
			i,s = sess
			res[s.sid] = {
				'type'        => s.type.to_s,
				'tunnel_local'=> s.tunnel_local.to_s,
				'tunnel_peer' => s.tunnel_peer.to_s,
				'via_exploit' => s.via_exploit.to_s,
				'via_payload' => s.via_payload.to_s,
				'desc'        => s.desc.to_s,
				'workspace'   => s.workspace.to_s,
				'target_host' => s.target_host.to_s
			}
		end
		res
	end

	def stop(token, sid)
		authenticate(token)
		s = _find_session(sid)
		s.kill
		{ "result" => "success" }
	end

	def shell_read(token, sid)
		authenticate(token)
		s = _find_session(sid)
		if(s.type != "shell")
			raise ::XMLRPC::FaultException.new(403, "session is not a shell")
		end

		if(not s.rstream.has_read_data?(0))
			{ "data" => "" }
		else
			{ "data" => s.shell_read }
		end
	end

	def shell_write(token, sid, data)
		authenticate(token)
		s = _find_session(sid)
		if(s.type != "shell")
			raise ::XMLRPC::FaultException.new(403, "session is not a shell")
		end

		{ "write_count" => s.shell_write(data) }
	end

	def meterpreter_read(token, sid)
		authenticate(token)
		s = _find_session(sid)
		if(s.type != "meterpreter")
			raise ::XMLRPC::FaultException.new(403, "session is not meterpreter")
		end

		if not s.user_output.respond_to? :dump_buffer
			s.init_ui(nil, Rex::Ui::Text::Output::Buffer.new)
		end

		data = s.user_output.dump_buffer
		{ "data" => data }
	end

	#
	# Run a single meterpreter console command
	#
	def meterpreter_write(token, sid, data)
		authenticate(token)
		s = _find_session(sid)
		if(s.type != "meterpreter")
			raise ::XMLRPC::FaultException.new(403, "session is not meterpreter")
		end

		if not s.user_output.respond_to? :dump_buffer
			s.init_ui(nil, Rex::Ui::Text::Output::Buffer.new)
			s.user_output.extend BufferedIO
		end

		Thread.new { s.console.run_single(data) }

		{}
	end

	def meterpreter_script(token, sid, data)
		meterpreter_write(token, sid, "run #{data}")
	end

protected

	def _find_session(sid)
		s = @framework.sessions[sid.to_i]
		if(not s)
			raise ::XMLRPC::FaultException.new(404, "unknown session")
		end
		s
	end

end
end
end

