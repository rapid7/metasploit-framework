#
# Author: Metasploit LLC
# Description: The AJAX console controller of msfweb
#

class SessionsController < ApplicationController
	layout 'windows'

	def list
		@sessions = Session.find_all()
	end

	def stop
	end

	def interact
		cid = params[:id].to_i

		$msfweb.connect_session(cid)
		
		if(params[:cmd])
			$msfweb.write_session(cid, params[:cmd] + "\n")
		end


		if (params[:read])	
			$msfweb.connect_session(cid)
			out = $msfweb.read_session(cid) || ''
			out = out.unpack('C*').map{|c| sprintf("%%%.2x", c)}.join
			script =  "// Metasploit Web Session Data\n"
			script += "var ses_update = unescape('#{out}');\n"
			send_data(script, :type => "text/javascript")
		end
	end
end

