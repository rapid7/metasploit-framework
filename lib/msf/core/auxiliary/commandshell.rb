# -*- coding: binary -*-

require 'msf/base/sessions/command_shell_options'

module Msf

###
#
# This module provides methods for scanning modules that yield
# Command Shell sessions.
#
###

module Auxiliary::CommandShell

	include Msf::Sessions::CommandShellOptions

	#
	# Ghetto
	#
	module CRLFLineEndings
		def put(str, opts={})
			return super if not str
			super(str.strip + "\r\n", opts)
		end
		def write(str, opts={})
			return super if not str
			super(str.strip + "\r\n", opts)
		end
	end


	def start_session(obj, info, ds_merge, crlf = false, sock = nil)
		if crlf
			# Windows telnet server requires \r\n line endings and it doesn't
			# seem to affect anything else.
			obj.sock.extend(CRLFLineEndings)
		end

		sock ||= obj.sock
		sess = Msf::Sessions::CommandShell.new(sock)
		sess.set_from_exploit(obj)
		sess.info = info

		# Clean up the stored data
		sess.exploit_datastore.merge!(ds_merge)

		# Prevent the socket from being closed
		obj.sockets.delete(sock)
		obj.sock = nil if obj.respond_to? :sock

		framework.sessions.register(sess)
		sess.process_autoruns(datastore)

		sess
	end

end
end
