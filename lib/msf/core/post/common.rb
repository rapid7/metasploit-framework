module Msf
class Post

module Common

	# Execute given command as hidden and channelize, output of command given as a multiline string.
	# For certain versions of Meterpreter options can not be included in the cmd var
	def cmd_exec(cmd, opts=nil, time_out=15)
		case session.type
		when /meterpreter/
			if opts.nil? and cmd =~ /\s*/
				opts = Shellwords.shellwords(cmd)
				cmd = opts.shift
				opts = opts.join
			end
			session.response_timeout = time_out
			process = session.sys.process.execute(cmd, opts, {'Hidden' => true, 'Channelized' => true})
			o = ""
			while (d = process.channel.read)
				break if d == ""
				o << d
			end
			process.channel.close
			process.close
		when /shell/
			o = session.shell_command_token("#{cmd} #{opts}", time_out)
			o.chomp! if o
		end
		return "" if o.nil?
		return o
	end

end
end
end
