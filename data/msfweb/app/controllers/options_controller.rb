#
# Original version is Copyright (c) 2007 Mike Whitehead <mwhite22[at]caledonian.ac.uk>
# Added to Metasploit under the terms of the Metasploit Framework License v1.2
#
# Description: MSFWeb Options controller (Skinning, etc)
#

class OptionsController < ApplicationController
	layout 'windows'

	def index
		@force_reload = false
		
		p params
		p cookies
		
		if (params[:style])
			cookies[:style] = params[:style]
			@force_reload = true
		end
	end
end

