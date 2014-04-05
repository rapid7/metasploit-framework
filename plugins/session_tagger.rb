#
# $Id$
# $Revision$
#

module Msf

###
#
# This class hooks all session creation events and allows automated interaction
# This is only an example of what you can do with plugins
#
###

class Plugin::SessionTagger < Msf::Plugin


  include Msf::SessionEvent

  def on_session_open(session)
    print_status("Hooked session #{session.sid} / #{session.session_host}")

    # XXX: Determine what type of session this is before writing to it

    if (session.interactive?)
      session.shell_write("MKDIR C:\\TaggedBy#{ENV['USER']}\n")
      session.shell_write("mkdir /tmp/TaggedBy#{ENV['USER']}\n")
    end

    #
    # Read output with session.shell_read()
    #
  end

  def on_session_close(session,reason='')
    print_status("Hooked session #{session.sid} is shutting down")
  end

  def initialize(framework, opts)
    super
    self.framework.events.add_session_subscriber(self)
  end

  def cleanup
    self.framework.events.remove_session_subscriber(self)
  end

  def name
    "session_tagger"
  end

  def desc
    "Automatically interacts with new sessions"
  end

end
end

