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
			raise ::XMLRPC::FaultException.new(404, "unknown session")
		end
		s.kill
		{ "result" => "success" }
	end

	def shell_read(token, sid)
		s = _valid_session(token,sid,"shell")

		begin
			if(not s.rstream.has_read_data?(0.001))
				{ "data" => "", "encoding" => "base64" }
			else
				data = s.shell_read
				{ "data" => Rex::Text.encode_base64(data), "encoding" => "base64" }
			end
		rescue ::Exception => e
			raise ::XMLRPC::FaultException.new(500, "session disconnected: #{e.class} #{e}")
		end
	end

	def shell_write(token, sid, data)
		s = _valid_session(token,sid,"shell")
		buff = Rex::Text.decode_base64(data)
		cnt = s.shell_write(buff)

		begin
			{ "write_count" => cnt }
		rescue ::Exception => e
			raise ::XMLRPC::FaultException.new(500, "session disconnected: #{e.class} #{e}")
		end
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
		# XXX Ghetto
		#
		# This should really be handled on the sessions' input/output handles
		# but this gets it working for right now.
		#
		if data.length > 0
			@framework.events.on_session_output(s, data)
		end
		{ "data" => Rex::Text.encode_base64(data), "encoding" => "base64" }
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
		# This is already covered by the meterpreter console's on_command_proc
		# so don't do it here
		#@framework.events.on_session_command(s, buff)
		interacting = false
		s.channels.each_value do |ch|
			interacting ||= ch.respond_to?('interacting') && ch.interacting
		end
		if interacting
			s.user_input.put(buff+"\n")
		else
			Thread.new(s) { |sess| sess.console.run_single(buff) }
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

	def meterpreter_script(token, sid, data)
		s = _valid_session(token,sid,"meterpreter")

		if not s.user_output.respond_to? :dump_buffer
			s.init_ui(Rex::Ui::Text::Input::Buffer.new, Rex::Ui::Text::Output::Buffer.new)
		end

		Thread.new(s) { |sess| sess.console.run_single("run #{data}") }
		{}
	end

protected

	def _valid_session(token,sid,type)
		authenticate(token)
		s = @framework.sessions[sid.to_i]
		if(not s)
			raise ::XMLRPC::FaultException.new(404, "unknown session")
		end
		if(s.type != type)
			raise ::XMLRPC::FaultException.new(403, "session is not "+type)
		end
		s
	end

end
end
end

