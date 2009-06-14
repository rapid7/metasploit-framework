#
# Original version is Copyright (c) 2006 LMH <lmh[at]info-pull.com>
# Added to Metasploit under the terms of the Metasploit Framework License v1.2
#
# Description: The auxiliary controller of msfweb v.3. Handles views, listing
# and other actions related to auxiliary modules. Code and processing goes here.
# Instance variables, final values, etc, go into views.

class AuxiliariesController < ApplicationController
  layout 'windows'
    
def list
end

def view
	@tmod = get_view_for_module("auxiliary", params[:refname])
	
	unless @tmod
	 render_text "Unknown module specified."
	end
end

def config
	# Retrieve object to module with the given refname
	@tmod     = get_view_for_module("auxiliary", params[:refname])
	unless @tmod
		render_text "Unknown module specified."
	end

	if (@tmod.actions.length > 0)
		@act = @tmod.actions[params[:act].to_i]
		unless @act
			render_text "Unknown action specified."
		end
	end	
	
	@cur_step = nil
	if params[:step]
		@cur_step = params[:step]
	end

	if @cur_step == "run"
		
		# Always show the option page after an exploit is launched
		@cur_step = "config"
		
		# Create a new console driver instance
		@cid = $msfweb.create_console()
		@con = $msfweb.consoles[@cid]

		# Use the selected module
		@con.execute("use auxiliary/#{@tmod.refname}")

		@aux = @con.active_module
		
		if (@act)
			@aux.datastore['ACTION']  = @act.name
		end

		# Configure the selected options
		params.each_key do |k|
			aopt = k.to_s.match(/^aopt_/) ? true : false
			name = k.to_s.gsub(/^.opt_/, '')

			if (aopt)
				if (params[k] and params[k].to_s.length > 0)
					@aux.datastore[name] = params[k].to_s
				end
			end
		end
		
		begin
			@aux.options.validate(@aux.datastore)
			@con.write("run\n")
			@aux_console = @cid
		rescue ::Exception => e
			$msfweb.destroy_console(@cid)
			@aux_error = e.to_s
		end	
	end
	

end

end
