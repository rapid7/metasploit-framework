require 'msf/core'
require 'msf/core/auxiliary'

###
#
# This class is here to implement advanced features for AIX-based
# payloads. AIX payloads are expected to include this module if
# they want to support these features.
#
###
module Msf::Payload::Aix

	include Msf::Auxiliary::Report

	#
	# This mixin is chained within payloads that target the AIX platform.
	# It provides special prepends, to support things like chroot and setuid
	# and detect AIX version.
	#
	def initialize(info = {})
		ret = super(info)

		register_options(
			[
				Msf::OptString.new('AIX', [ true, 'IBM AIX Version', '6.1.4' ]),
			], Msf::Payload::Aix)

		ret
	end


	#
	# Overload the generate() call to prefix our stubs and detect AIX version
	#
	def generate(*args)
		@aix = datastore['AIX']

		#if not assoc_exploit.nil?
		#	note = find_note(assoc_exploit.rhost, 'AIX')

		#	if not note.nil?
		#		@aix = note['data']
		#	end
		#end

		__CAL = 511

		case @aix
		when '6.1.4'
			__NR_execve      = 7
			__NR_getpeername = 211
			__NR_accept      = 237
			__NR_listen      = 240
			__NR_bind        = 242
			__NR_socket      = 243
			__NR_connect     = 244
			__NR_close       = 278
			__NR_kfcntl      = 658

		when '6.1.3'
			__NR_execve      = 7
			__NR_getpeername = 205
			__NR_accept      = 232
			__NR_listen      = 235
			__NR_bind        = 237
			__NR_socket      = 238
			__NR_connect     = 239
			__NR_close       = 272
			__NR_kfcntl      = 644

		when '6.1.2'
			__NR_execve      = 7
			__NR_getpeername = 205
			__NR_accept      = 232
			__NR_listen      = 235
			__NR_bind        = 237
			__NR_socket      = 238
			__NR_connect     = 239
			__NR_close       = 272
			__NR_kfcntl      = 635

		when '6.1.1'
			__NR_execve      = 7
			__NR_getpeername = 202
			__NR_accept      = 229
			__NR_listen      = 232
			__NR_bind        = 234
			__NR_socket      = 235
			__NR_connect     = 236
			__NR_close       = 269
			__NR_kfcntl      = 614

		when '6.1.0'
			__NR_execve      = 6
			__NR_getpeername = 203
			__NR_accept      = 229
			__NR_listen      = 232
			__NR_bind        = 234
			__NR_socket      = 235
			__NR_connect     = 236
			__NR_close       = 269
			__NR_kfcntl      = 617

		when '5.3.10', '5.3.9', '5.3.8', '5.3.7'
			__NR_execve      = 6
			__NR_getpeername = 198
			__NR_accept      = 214
			__NR_listen      = 215
			__NR_bind        = 216
			__NR_socket      = 217
			__NR_connect     = 218
			__NR_close       = 245
			__NR_kfcntl      = 493

		end

		__NC_execve      = -(__CAL - __NR_execve)
		__NC_getpeername = -(__CAL - __NR_getpeername)
		__NC_accept      = -(__CAL - __NR_accept)
		__NC_listen      = -(__CAL - __NR_listen)
		__NC_bind        = -(__CAL - __NR_bind)
		__NC_socket      = -(__CAL - __NR_socket)
		__NC_connect     = -(__CAL - __NR_connect)
		__NC_close       = -(__CAL - __NR_close)
		__NC_kfcntl      = -(__CAL - __NR_kfcntl)

		cal = "\x38\x5d"
		@cal_execve      = cal + [__NC_execve].pack('n')
		@cal_getpeername = cal + [__NC_getpeername].pack('n')
		@cal_accept      = cal + [__NC_accept].pack('n')
		@cal_listen      = cal + [__NC_listen].pack('n')
		@cal_bind        = cal + [__NC_bind].pack('n')
		@cal_socket      = cal + [__NC_socket].pack('n')
		@cal_connect     = cal + [__NC_connect].pack('n')
		@cal_close       = cal + [__NC_close].pack('n')
		@cal_kfcntl      = cal + [__NC_kfcntl].pack('n')

		return ''
	end

protected
	attr_accessor :aix
	attr_accessor :cal_execve
	attr_accessor :cal_getpeername
	attr_accessor :cal_accept
	attr_accessor :cal_bind
	attr_accessor :cal_socket
	attr_accessor :cal_connect
	attr_accessor :cal_close
	attr_accessor :cal_kfcntl

end
