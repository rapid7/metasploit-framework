# Author: LMH <lmh@info-pull.com>
# Description: The AJAX console controller of msfweb v.3. Handles commands,
# operations and sessions carried over the web interface.
class ConsoleController < ApplicationController

	#
	# Show the working shell and related facilities.
	#
	def index
	
		cid = params[:id]
		
		if (not (cid and $msfweb.consoles[cid]))
			cid = $msfweb.create_console
			redirect_to :id => cid
			return
		end
		
		@cid = params[:id]
		@console = $msfweb.consoles[@cid]
		
		if(params[:cmd])
			if (params[:cmd].strip.length > 0)
				@console.write(params[:cmd] + "\n") 
			end
			send_data(@console.read(), :type => "application/octet-stream")
		end
	end

end
