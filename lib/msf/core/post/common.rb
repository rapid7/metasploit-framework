module Msf
class Post

module Common

	# Execute given command as hidden and channelized, output of command given as a multiline string.
	# For certain versions of Meterpreter options can not be included in the cmd var
	def cmd_exec(cmd,opts = nil)
		session.response_timeout=120
		cmd = session.sys.process.execute(cmd, opts, {'Hidden' => true, 'Channelized' => true})
		o = ""
		while(d = cmd.channel.read)
			o << d
			break if d == ""
		end
		cmd.channel.close
		return o
	end

end
end
end