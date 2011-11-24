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
				'info'        => s.info.to_s,
				'workspace'   => s.workspace.to_s,
				'target_host' => s.target_host.to_s,
				'username'    => s.username.to_s,
				'uuid'        => s.uuid.to_s,
				'exploit_uuid' => s.exploit_uuid.to_s,
				'routes'       => s.routes.join(",")
			}
			if(s.type.to_s == "meterpreter")
				res[s.sid]['platform'] = s.platform.to_s
			end
		end
		res
	end

	def stop(token, sid)
		authenticate(token)
		s = @framework.sessions[sid.to_i]
		if(not s)
			raise ::XMLRPC::FaultException.new(404, "unknown session while stopping")
		end
		s.kill
		{ "result" => "success" }
	end

	# Shell read is now a positon-aware reader of the shell's associated
	# ring buffer. For more direct control of the pointer into a ring
	# buffer, a client can instead use ring_read, and note the returned
	# sequence number on their own (making multiple views into the same
	# session possible, regardless of position in the stream)
	def shell_read(token, sid, ptr=nil)
		_valid_session(token,sid,"shell")
		# @session_sequence tracks the pointer into the ring buffer
		# data of sessions (by sid) in order to emulate the old behavior
		# of shell_read
		@session_sequence ||= {}
		@session_sequence[sid] ||= 0
		ring_buffer = ring_read(token,sid,(ptr || @session_sequence[sid]))
		if not (ring_buffer["seq"].nil? || ring_buffer["seq"].empty?)
			@session_sequence[sid] = ring_buffer["seq"].to_i
		end
		return ring_buffer
	end

	# shell_write is pretty much totally identical to ring_put
	def shell_write(token, sid, data)
		_valid_session(token,sid,"shell")
		ring_put(token,sid,data)
	end

	def shell_upgrade(token, sid, lhost, lport)
		s = _valid_session(token,sid,"shell")
		s.exploit_datastore['LHOST'] = lhost
		s.exploit_datastore['LPORT'] = lport
		s.execute_script('spawn_meterpreter', nil)
		{ "result" => "success" }
	end

	def meterpreter_read(token, sid)
		s = _valid_session(token,sid,"meterpreter")

		if not s.user_output.respond_to? :dump_buffer
			s.init_ui(Rex::Ui::Text::Input::Buffer.new, Rex::Ui::Text::Output::Buffer.new)
		end

		data = s.user_output.dump_buffer
		{ "data" => Rex::Text.encode_base64(data), "encoding" => "base64" }
	end

	def ring_read(token, sid, ptr=nil)
		authenticate(token)
		s = _valid_session(token,sid,"ring")
		begin
			res = s.ring.read_data(ptr)
			{ "seq" => res[0].to_s, "data" =>(Rex::Text.encode_base64(res[1].to_s)), "encoding" => "base64"}
		rescue ::Exception => e
			raise ::XMLRPC::FaultException.new(500, "session disconnected: #{e.class} #{e}")
		end
	end

	def ring_put(token, sid, data)
		authenticate(token)
		s = _valid_session(token,sid,"ring")
		buff = Rex::Text.decode_base64(data)
		begin
			res = s.shell_write(buff)
			{ "write_count" => res.to_s}
		rescue ::Exception => e
			raise ::XMLRPC::FaultException.new(500, "session disconnected: #{e.class} #{e}")
		end
	end

	def ring_last(token, sid)
		authenticate(token)
		s = _valid_session(token,sid,"ring")
		{ "seq" => s.ring.last_sequence.to_s }
	end

	def ring_clear(token, sid)
		authenticate(token)
		s = _valid_session(token,sid,"ring")
		res = s.ring.clear_data
		if res.compact.empty?
			{ "result" => "success"}
		else # Doesn't seem like this can fail. Maybe a race?
			{ "result" => "failure"}
		end
	end

	#
	# Run a single meterpreter console command
	#
	def meterpreter_write(token, sid, data)
		s = _valid_session(token,sid,"meterpreter")

		if not s.user_output.respond_to? :dump_buffer
			s.init_ui(Rex::Ui::Text::Input::Buffer.new, Rex::Ui::Text::Output::Buffer.new)
		end

		buff = Rex::Text.decode_base64(data)

		interacting = false
		s.channels.each_value do |ch|
			interacting ||= ch.respond_to?('interacting') && ch.interacting
		end
		if interacting
			s.user_input.put(buff+"\n")
		else
			@framework.threads.spawn("MeterpreterRunSingle", false, s) { |sess| sess.console.run_single(buff) }
		end
		{}
	end

	def meterpreter_session_detach(token,sid)
		s = _valid_session(token,sid,"meterpreter")
		s.channels.each_value do |ch|
			if(ch.respond_to?('interacting') && ch.interacting)
				ch.detach()
				return { "result" => "success" }
			end
		end
		{ "result" => "failure" }
	end

	def meterpreter_session_kill(token,sid)
		s = _valid_session(token,sid,"meterpreter")
		s.channels.each_value do |ch|
			if(ch.respond_to?('interacting') && ch.interacting)
				ch._close
				return { "result" => "success" }
			end
		end
		{ "result" => "failure" }
	end

	def meterpreter_tabs(token,sid, line)
		s = _valid_session(token,sid,"meterpreter")
		{ "tabs" => s.console.tab_complete(line) }
	end

	# runs a meterpreter command even if interacting with a shell or other channel
	def meterpreter_run_single(token, sid, data)
		s = _valid_session(token,sid,"meterpreter")

		if not s.user_output.respond_to? :dump_buffer
			s.init_ui(Rex::Ui::Text::Input::Buffer.new, Rex::Ui::Text::Output::Buffer.new)
		end

		@framework.threads.spawn("MeterpreterRunSingle", false, s) { |sess| sess.console.run_single(data) }
		{}
	end

	def meterpreter_script(token, sid, data)
		meterpreter_run_single(token, sid, "run #{data}")
	end

	def compatible_modules(token, sid)
		authenticate(token)
		ret = []

		mtype = "post"
		names = @framework.post.keys.map{ |x| "post/#{x}" }
		names.each do |mname|
			m = _find_module(mtype, mname)
			next if not m.session_compatible?(sid)
			ret << m.fullname
		end
		ret
	end

private

	def _find_module(mtype,mname)
		mod = @framework.modules.create(mname)

		if(not mod)
			raise ::XMLRPC::FaultException.new(404, "unknown module")
		end

		mod
	end

	def _valid_session(token,sid,type)
		authenticate(token)
		s = @framework.sessions[sid.to_i]
		if(not s)
			raise ::XMLRPC::FaultException.new(404, "unknown session while validating")
		end
		if type == "ring"
			if not s.respond_to?(:ring)
				raise ::XMLRPC::FaultException.new(403, "session #{s.type} does not support ring operations")
			end
		elsif(s.type != type)
			raise ::XMLRPC::FaultException.new(403, "session is not "+type)
		end
		s
	end

end
end
end

