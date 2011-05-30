module Msf
class Post

module Common

	# Execute given command as hidden and channelize, output of command given as a multiline string.
	# For certain versions of Meterpreter options can not be included in the cmd var
	def cmd_exec(cmd,opts = nil,time_out = 15)
		case session.type
		when /meterpreter/
			session.response_timeout = time_out
			cmd = session.sys.process.execute(cmd, opts, {'Hidden' => true, 'Channelized' => true})
			o = ""
			while(d = cmd.channel.read)
			o << d
				break if d == ""
			end
			cmd.channel.close
		when /shell/
			o = session.shell_command_token("#{cmd} #{opts}",time_out).chomp
		end
		return o
	end

end
end
end