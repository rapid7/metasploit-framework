#!/usr/bin/ruby

require 'Rex/Post/Process'
require 'Rex/Post/Meterpreter/Packet'
require 'Rex/Post/Meterpreter/Client'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Stdapi'

require 'Rex/Post/Meterpreter/Extensions/Stdapi/Sys/ProcessSubsystem/Image'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Sys/ProcessSubsystem/Memory'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Sys/ProcessSubsystem/Thread'

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

	# Returns the process identifier of the process supplied in key if it's
	# valid
	def Process.[](key)
		each_process { |p|
			if (p['name'].downcase == key.downcase)
				return p['pid']
			end
		}

		return nil
	end

	# Attachs to the supplied process with a given set of permissions
	def Process.open(pid = nil, perms = nil)
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

		return _open(pid, real_perms)	
	end

	# Low-level process open
	def Process._open(pid, perms, inherit = false)
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
			return self.new(pid, handle)
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

	# Enumerates all of the elements in the array returned by get_processes
	def Process.each_process(&block)
		self.get_processes.each(&block)
	end

	# Returns an array of processes with hash objects that have
	# keys for 'pid', 'name', and 'path'.
	def Process.get_processes
		request   = Packet.create_request('stdapi_sys_process_get_processes')
		processes = []

		response = client.send_request(request)

		response.each(TLV_TYPE_PROCESS_GROUP) { |p|
			processes << 
				{
					'pid'  => p.get_tlv_value(TLV_TYPE_PID),
					'name' => p.get_tlv_value(TLV_TYPE_PROCESS_NAME),
					'path' => p.get_tlv_value(TLV_TYPE_PROCESS_PATH),
				}
		}

		return processes
	end


	##
	#
	# Instance methods
	#
	##

	# Initializes the process instance and its aliases
	def initialize(pid, handle)
		self.client = self.class.client
		self.handle = handle

		# If the process identifier is zero, then we must lookup the current
		# process identifier
		if (pid == 0)
			self.pid = client.sys.process.getpid
		else
			self.pid = pid
		end

		initialize_aliases(
			{
				'image'  => Rex::Post::Meterpreter::Extensions::Stdapi::Sys::ProcessSubsystem::Image.new(self),
				'memory' => Rex::Post::Meterpreter::Extensions::Stdapi::Sys::ProcessSubsystem::Memory.new(self),
				'thread' => Rex::Post::Meterpreter::Extensions::Stdapi::Sys::ProcessSubsystem::Thread.new(self),
			})
	end

	# Returns the executable name of the process
	def name
		return get_info()['name']
	end

	# Returns the path to the process' executable
	def path
		return get_info()['path']
	end

	# Closes the handle to the process that was opened
	def close
		request = Packet.create_request('stdapi_sys_process_close')

		request.add_tlv(TLV_TYPE_HANDLE, handle)

		response = client.send_request(request)

		handle = nil;

		return true
	end

	attr_reader   :client, :handle, :pid
protected
	attr_writer   :client, :handle, :pid

	# Gathers information about the process and returns a hash
	def get_info
		request = Packet.create_request('stdapi_sys_process_get_info')
		info    = {}

		request.add_tlv(TLV_TYPE_HANDLE, handle)

		# Send the request
		response = client.send_request(request)

		# Populate the hash
		info['name'] = response.get_tlv_value(TLV_TYPE_PROCESS_NAME)
		info['path'] = response.get_tlv_value(TLV_TYPE_PROCESS_PATH)

		return info
	end

end

end; end; end; end; end; end
