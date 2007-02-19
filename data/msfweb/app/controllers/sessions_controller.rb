#
# Author: Metasploit LLC
# Description: The AJAX console controller of msfweb
#

class SessionsController < ApplicationController
	layout 'windows'

	def list
		@sessions = Session.find_all()
	end
end

