# -*- coding: binary -*-
module Msf
module Handler

###
#
# This handlers implements port-based findsock handling.
#
###
module FindPort

  include Msf::Handler

  #
  # Returns the string representation of the handler type, in this case
  # 'find_port'.
  #
  def self.handler_type
    return "find_port"
  end

  #
  # Returns the connection oriented general handler type, in this case
  # 'find'.
  #
  def self.general_handler_type
    "find"
  end

  #
  # Initializes the find port handler and adds the client port option that is
  # required for port-based findsock payloads to function.
  #
  def initialize(info = {})
    super

    register_options(
      [
        Opt::CPORT(rand(64000) + 1024),
      ], Msf::Handler::FindPort)
  end

  #
  # Check to see if there's a shell on the supplied sock.  This check
  # currently only works for shells.
  #
  def handler(sock)
    return if not sock

    _find_prefix(sock)

    # Flush the receive buffer
    sock.get_once(-1, 1)

    # If this is a multi-stage payload, then we just need to blindly
    # transmit the stage and create the session, hoping that it works.
    if (self.payload_type != Msf::Payload::Type::Single)
      handle_connection(sock)
    # Otherwise, check to see if we found a session.  We really need
    # to improve this, as we could create a session when the exploit
    # really didn't succeed.
    else
      create_session(sock)
    end

    return self._handler_return_value
  end

protected

  #
  # Prefix to the stage if necessary.
  #
  def _find_prefix(sock)
  end

  #
  # Sends the identifier if there is one.
  #
  def _send_id(sock)
  end

  #
  # Wrapper to create session that makes sure we actually have a session to
  # create...
  #
  def create_session(sock, opts={})
    go = true

    # Give the payload a chance to run
    Rex::ThreadSafe.sleep(1.5)

    # This is a hack.  If the session is a shell, we check to see if it's
    # functional by sending an echo which tells us whether or not we're good
    # to go.
    if (self.session and self.session.type == 'shell')
      go = _check_shell(sock)
    else
      print_status("Trying to use connection...")
    end

    # If we're good to go, create the session.
    rv = (go == true) ? super : nil


    if (rv)
      self._handler_return_value = Claimed
    end

    return rv
  end

  #
  # Checks to see if a shell has been allocated on the connection.  This is
  # only done for payloads that use the CommandShell session.
  #
  def _check_shell(sock)
    ebuf = Rex::Text.rand_text_alphanumeric(16)

    # Send any identifying information that the find sock may need on
    # the other side, such as a tag.  If we do actually send something,
    # wait a bit longer to let the remote side find us.
    if (_send_id(sock))
      Rex::ThreadSafe.sleep(1.5)
    end

    # Make sure the read buffer is empty before we test for a shell
    sock.get_once(-1,1)
    # Check to see if the shell exists
    sock.put("\necho #{ebuf}\n")

    # Try to read a response
    rbuf = sock.get_once

    # If it contains our string, then we rock
    if (rbuf =~ /#{ebuf}/)
      print_status("Found shell.")

      return true
    else
      return false
    end
  end

  attr_accessor :_handler_return_value # :nodoc:

end

end
end

