module Msf
module Ui
module Console

###
#
# Handles events of various types that are sent from the framework.
#
###
module FrameworkEventManager

	include Msf::SessionEvent

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

		if (Msf::Logging.session_logging_enabled? == true)
			Msf::Logging.start_session_log(session)
		end
	end

	#
	# Called when a session is closed and removed from the framework.
	#
	def on_session_close(session)
		if (session.interacting == true)
			output.print_line
		end

		# If logging had been enabled for this session, stop it now.
		Msf::Logging::stop_session_log(session)

		output.print_status("#{session.desc} session #{session.name} closed.")
	end

end

end
end
end