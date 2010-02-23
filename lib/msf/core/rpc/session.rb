require 'rex'
require 'rex/io/bidirectional_pipe'

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
			{ "data" => s.read_shell }
		end
	end

	def shell_write(token, sid, data)
		authenticate(token)
		s = _find_session(sid)
		if(s.type != "shell")
			raise ::XMLRPC::FaultException.new(403, "session is not a shell")
		end

		{ "write_count" => s.write_shell(data) }
	end

	def meterpreter_read(token, sid)
		authenticate(token)
		s = _find_session(sid)
		if(s.type != "meterpreter")
			raise ::XMLRPC::FaultException.new(403, "session is not meterpreter")
		end
		if s.console.output.respond_to? :read_buff
			data = s.console.output.read_buff
		else
			s.console.output.extend BufferedIO
			data = ''
		end
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

		# We have to start buffering the console output before running the
		# command so we don't lose any output.
		if not s.console.output.respond_to? :read_buff
			s.console.output.extend BufferedIO
		end
		found = s.console.run_single(data)
		if not found
			raise ::XMLRPC::FaultException.new(404, "command not found")
		end

		{ "data" => found }
	end

	def meterpreter_script(token, sid, data)
		meterpreter_write("run #{data}")
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

# Ghetto
module BufferedIO
	alias_method :orig_print, :print
	def read_buff
		self.buffer ||= ''
		buf = self.buffer.dup
		self.buffer = ''
		buf
	end
	def print(msg)
		self.buffer ||= ''
		self.buffer << msg
		orig_print(msg)
	end
	def print_line(msg); print(msg +"\n"); end
	attr_accessor :buffer
end

