#
# Author: Metasploit LLC
# Description: The AJAX console controller of msfweb
#
class ConsoleController < ApplicationController

	#
	# Show the working shell and related facilities.
	#
	def index

		cid = params[:id]

		if (not (cid and $msfweb.consoles[cid]))
			cid = $msfweb.create_console
			
			if (params[:sid])
				$msfweb.consoles[cid].write("sessions -i #{params[:sid]}\n")
				$msfweb.consoles[cid].write("\n\n")
			end
			
			redirect_to :id => cid
			return
		end


		script = "// Metasploit Web Console Data\n"
		out    = ""
		
		@cid = params[:id]
		@console = $msfweb.consoles[@cid]


		if(params[:cmd])
			@console.write(params[:cmd] + "\n")
		end

		if(params[:read])
			out = @console.read() || ''
		end

		
		if(params[:special])
			case params[:special]
			when 'kill'
				@console.session_kill
			when 'detach'		
				@console.session_detach	
			end
		end
		
		if(params[:tab])
			opts = []
			cmdl = params[:tab]
			out  = ""

			if (not @console.busy and params[:tab].strip.length > 0)
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

					out << "\n" + opts.map{ |c| ">> " + c }.join("\n")
				end
			end

			tln = cmdl.unpack('C*').map{|c| sprintf("%%%.2x", c)}.join
			script += "var con_tabbed = unescape('#{tln}');\n"			
		end
	
		if(params[:read])
		
			out = out.unpack('C*').map{|c| sprintf("%%%.2x", c)}.join
			pro = @console.prompt.unpack('C*').map{|c| sprintf("%%%.2x", c)}.join
			if (@console.busy)
				pro = '(running)'.unpack('C*').map{|c| sprintf("%%%.2x", c)}.join
			end

			script += "var con_prompt = unescape('#{pro}');\n"
			script += "var con_update = unescape('#{out}');\n"

			send_data(script, :type => "text/javascript")
		end
	end

end
