module Msf
module Ui
module Console

###
#
# FrameworkEventManager
# ---------------------
#
# Handles events of various types that are sent from the framework.
#
###
module FrameworkEventManager

	include Msf::SessionEvents

	#
	# Subscribes to the framework as a subscriber of various events.
	#
	def register_event_handlers
		framework.events.add_session_subscriber(self)
	end

	#
	# Unsubscribes from the framework.
	#
	def deregister_event_handlers
		framework.events.remove_session_subscriber(self)
	end

	#
	# Called when a session is registered with the framework.
	#
	def on_session_open(session)
		output.print_status("#{session.desc} session #{session.name} opened (#{session.tunnel_to_s})")
		output.print_line
	end

	#
	# Called when a session is closed and removed from the framework.
	#
	def on_session_close(session)
		output.print_line
		output.print_status("#{session.desc} session #{session.name} closed.")
	end

end

end
end
end
