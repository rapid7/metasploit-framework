
###
#
# Event notifications that affect sessions.
#
###
module Msf::SessionEvent

  #
  # Called when a session is opened.
  #
  def on_session_open(session)
  end

  #
  # Called when a session is closed.
  #
  def on_session_close(session, reason='')
  end

  #
  # Called when the user interacts with a session.
  #
  def on_session_interact(session)
  end

  #
  # Called when the user writes data to a session.
  #
  def on_session_command(session, command)
  end

  #
  # Called when output comes back from a user command.
  #
  def on_session_output(session, output)
  end

  #
  # Called when a file is uploaded.
  #
  def on_session_upload(session, local_path, remote_path)
  end

  #
  # Called when a file is downloaded.
  #
  def on_session_download(session, remote_path, local_path)
  end

  #
  # Called when a file is deleted.
  #
  def on_session_filedelete(session, path)
  end
end