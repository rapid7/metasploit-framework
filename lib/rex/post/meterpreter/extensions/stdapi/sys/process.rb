#!/usr/bin/ruby

require 'Rex/Post/Process'
require 'Rex/Post/Meterpreter/Packet'
require 'Rex/Post/Meterpreter/Client'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Stdapi'

require 'Rex/Post/Meterpreter/Extensions/Stdapi/Sys/ProcessSubsystem/Memory'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Sys

##
#
# Process
# -------
#
# This class implements the Rex::Post::Process interface.
#
##
class Process < Rex::Post::Process

	include Rex::Post::Meterpreter::ObjectAliasesContainer

	##
	#
	# Class methods
	#
	##

	class <<self
		attr_accessor :client
	end

	# Attachs to the supplied process with a given set of permissions
	def Process.attach(pid = nil, perms = nil)
		real_perms = 0

		if (perms == nil)
			perms = PROCESS_ALL
		end

		if (perms & PROCESS_READ)
			real_perms |= PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
		end

		if (perms & PROCESS_WRITE)
			real_perms |= PROCESS_SET_SESSIONID | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION
		end

		if (perms & PROCESS_EXECUTE)
			real_perms |= PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_CREATE_PROCESS | PROCESS_SUSPEND_RESUME
		end

		return _attach(pid, real_perms)	
	end

	# Low-level process attach
	def Process._attach(pid, perms, inherit = false)
		request = Packet.create_request('stdapi_sys_process_attach')

		if (pid == nil)
			pid = 0
		end

		# Populate the request
		request.add_tlv(TLV_TYPE_PID, pid)
		request.add_tlv(TLV_TYPE_PROCESS_PERMS, perms)
		request.add_tlv(TLV_TYPE_INHERIT, inherit)

		# Transmit the request
		response = self.client.send_request(request)
		handle   = response.get_tlv_value(TLV_TYPE_HANDLE)

		# If the handle is valid, allocate a process instance and return it
		if (handle != nil)
			return self.new(handle)
		end

		return nil
	end

	# Executes an application using the arguments provided
	def Process.execute(opts)
		raise NotImplementedError
	end

	# Gets the process id that the remote side is executing under
	def Process.getpid
		request = Packet.create_request('stdapi_sys_process_getpid')

		response = client.send_request(request)

		return response.get_tlv_value(TLV_TYPE_PID)
	end


	##
	#
	# Instance methods
	#
	##

	def initialize(handle)
		self.client = self.class.client
		self.handle = handle

		initialize_aliases(
			{
				'memory' => Rex::Post::Meterpreter::Extensions::Stdapi::Sys::ProcessSubsystem::Memory.new(self),
			})
	end


	attr_reader   :client, :handle
protected
	attr_writer   :client, :handle

end

end; end; end; end; end; end
