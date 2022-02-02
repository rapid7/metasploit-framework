# -*- coding: binary -*-
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
    select(nil,nil,nil,0.125) # Give the session time enough to register itself properly.
    output.print_status("#{session.desc} session #{session.name} opened (#{session.tunnel_to_s}) at #{Time.now}")
    if (Msf::Logging.session_logging_enabled? == true)
      Msf::Logging.start_session_log(session)
    end
  end

  def on_session_fail(reason='')
  end

  #
  # Called when a session is closed and removed from the framework.
  #
  def on_session_close(session, reason='')
    if (session.interacting == true)
      output.print_line
    end

    # If logging had been enabled for this session, stop it now.
    Msf::Logging::stop_session_log(session)

    msg = "#{session.session_host} - #{session.desc} session #{session.name} closed."
    if reason and reason.length > 0
      msg << "  Reason: #{reason}"
    end
    output.print_status(msg)
  end

end

end
end
end

