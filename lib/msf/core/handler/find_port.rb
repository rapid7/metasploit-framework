module Msf
module Handler

###
#
# FindPort
# --------
#
# This handlers implements port-based findsock handling.
#
###
module FindPort

	include Msf::Handler

	def self.handler_type
		return "find_port"
	end

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
		_find_prefix(sock)

		# Flush the receive buffer
		sock.get(1)

		# If this is a multi-stage payload, then we just need to blindly
		# transmit the stage and create the session, hoping that it works.
		if (self.payload_type != Msf::Payload::Type::Single)
			handle_connection(sock)
		# Otherwise, check to see if we found a session
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
	# Wrapper to create session that makes sure we actually have a session to
	# create...
	#
	def create_session(sock)
		go = true

		# Give the payload a chance to run
		Rex::ThreadSafe.sleep(1.5)
	
		# This is a hack.  If the session is a shell, we check to see if it's
		# functional by sending an echo which tells us whether or not we're good
		# to go.
		if (self.session.type == 'shell')
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

		# Check to see if the shell exists
		sock.put("echo #{ebuf}\n")

		# Try to read a response
		rbuf = sock.get(3)

		# If it contains our string, then we rock
		if (rbuf =~ /#{ebuf}/)
			print_status("Found shell...")

			return true
		else
			return false
		end
	end

	attr_accessor :_handler_return_value

end

end
end
