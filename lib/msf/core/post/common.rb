module Msf
class Post

module Common

	#Execute given command as hidden and channelized, output of command given as a multiline string.
	def cmd_exec(cmd)
		session.response_timeout=120
		cmd = session.sys.process.execute(cmd, nil, {'Hidden' => true, 'Channelized' => true})
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