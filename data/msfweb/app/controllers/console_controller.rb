#
# Author: Metasploit LLC
# Description: The AJAX console controller of msfweb
#
class ConsoleController < ApplicationController

	#
	# Show the working shell and related facilities.
	#
	def index

		# Work around rails stupidity
		if(not $webrick_hooked)

			$webrick.mount_proc("/_session") do |req, res|

				res['Content-Type'] = "text/javascript"

				m = req.path_info.match(/cid=(\d+)/)
				if (m and m[1] and $msfweb.consoles[m[1]])
					console = $msfweb.consoles[m[1]]

					out = ''
					tsp = Time.now.to_i

					# Poll the console output for 15 seconds
					while( tsp + 15 > Time.now.to_i and out.length == 0)
						out = console.read()
						select(nil, nil, nil, 0.25)
					end

					out = out.unpack('C*').map{|c| sprintf("%%%.2x", c)}.join
					pro = console.prompt.unpack('C*').map{|c| sprintf("%%%.2x", c)}.join

					script =  "// Metasploit Web Console Data\n"
					script += "var con_prompt = unescape('#{pro}');\n"
					script += "var con_update = unescape('#{out}');\n"

					res.body = script
				else
					res.body = '// Invalid console ID'
				end
			end

			$webrick_hooked = true
		end

		cid = params[:id]

		if (not (cid and $msfweb.consoles[cid]))
			cid = $msfweb.create_console
			redirect_to :id => cid
			return
		end

		@cid = params[:id]
		@console = $msfweb.consoles[@cid]

		if(params[:cmd])
			out = ''

			if (params[:cmd].strip.length > 0)
				@console.write(params[:cmd] + "\n")
			end

			out = out.unpack('C*').map{|c| sprintf("%%%.2x", c)}.join
			pro = @console.prompt.unpack('C*').map{|c| sprintf("%%%.2x", c)}.join

			script =  "// Metasploit Web Console Data\n"
			script += "var con_prompt = unescape('#{pro}');\n"
			script += "var con_update = unescape('#{out}');\n"

			send_data(script, :type => "text/javascript")
		end

		if(params[:tab])
			opts = []
			cmdl = params[:tab]
			out  = ""

			if (params[:tab].strip.length > 0)
				opts = @console.tab_complete(params[:tab]) || []
			end

			if (opts.length == 1)
				cmdl = opts[0]
			else
				if (opts.length == 0)
					# aint got nothin
				else

					cmd_top = opts[0]
					depth   = 0

					while (depth < cmd_top.length)
						match = true
						opts.each do |line|
							next if line[depth] == cmd_top[depth]
							match = false
							break
						end
						break if not match
						depth += 1
					end

					if (depth > 0)
						cmdl = cmd_top[0, depth]
					end

					out = "\n" + opts.map{ |c| " >> " + c }.join("\n")
				end
			end

			out = out.unpack('C*').map{|c| sprintf("%%%.2x", c)}.join
			pro = @console.prompt.unpack('C*').map{|c| sprintf("%%%.2x", c)}.join
			tln = cmdl.unpack('C*').map{|c| sprintf("%%%.2x", c)}.join

			script =  "// Metasploit Web Console Data\n"
			script += "var con_prompt = unescape('#{pro}');\n"
			script += "var con_update = unescape('#{out}');\n"
			script += "var con_tabbed = unescape('#{tln}');\n"

			send_data(script, :type => "text/javascript")
		end
	end

end
