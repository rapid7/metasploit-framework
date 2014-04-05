# -*- coding: binary -*-

require 'rex/post/meterpreter/client'
require 'rex/post/meterpreter/extensions/stdapi/constants'
require 'rex/post/meterpreter/extensions/stdapi/sys/thread'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Sys
module ProcessSubsystem

###
#
# Interfaces with a process' executing threads by enumerating,
# opening, and creating threads.
#
###
class Thread

  ##
  #
  # Constructor
  #
  ##

  #
  # Initializes a thread instance that operates in the context of the
  # supplied process instance.
  #
  def initialize(process)
    self.process = process
  end

  ##
  #
  # Process thread interaction
  #
  ##

  #
  # Opens an existing thread that is running within the context
  # of the process and returns a Sys::Thread instance.
  #
  def open(tid, access = THREAD_ALL)
    request = Packet.create_request('stdapi_sys_process_thread_open')
    real    = 0

    # Translate access
    if (access & THREAD_READ)
      real |= THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | SYNCHRONIZE
    end

    if (access & THREAD_WRITE)
      real |= THREAD_SET_CONTEXT | THREAD_SET_INFORMATION | THREAD_SET_THREAD_TOKEN | THREAD_IMPERSONATE | THREAD_DIRECT_IMPERSONATION
    end

    if (access & THREAD_EXECUTE)
      real |= THREAD_TERMINATE | THREAD_SUSPEND_RESUME | SYNCHRONIZE
    end

    # Add the thread identifier and permissions
    request.add_tlv(TLV_TYPE_THREAD_ID, tid)
    request.add_tlv(TLV_TYPE_THREAD_PERMS, real)

    # Transmit the request
    response = process.client.send_request(request)

    # Create a thread class instance
    return Rex::Post::Meterpreter::Extensions::Stdapi::Sys::Thread.new(
        process, response.get_tlv_value(TLV_TYPE_THREAD_HANDLE), tid)
  end

  #
  # Creates a new thread in the context of the process and
  # returns a Sys::Thread instance.
  #
  def create(entry, parameter = nil, suspended = false)
    request = Packet.create_request('stdapi_sys_process_thread_create')
    creation_flags = 0

    request.add_tlv(TLV_TYPE_PROCESS_HANDLE, process.handle)
    request.add_tlv(TLV_TYPE_ENTRY_POINT, entry)

    # Are we passing a parameter to the entry point of the thread?
    if (parameter != nil)
      request.add_tlv(TLV_TYPE_ENTRY_PARAMETER, parameter)
    end

    # Should we create the thread suspended?
    if (suspended)
      creation_flags |= CREATE_SUSPENDED
    end

    request.add_tlv(TLV_TYPE_CREATION_FLAGS, creation_flags)

    # Transmit the request
    response = process.client.send_request(request)


    thread_id     = response.get_tlv_value(TLV_TYPE_THREAD_ID)
    thread_handle = response.get_tlv_value(TLV_TYPE_THREAD_HANDLE)

    # Create a thread class instance
    return Rex::Post::Meterpreter::Extensions::Stdapi::Sys::Thread.new(
        process, thread_handle, thread_id)
  end

  #
  # Enumerate through each thread identifier.
  #
  def each_thread(&block)
    get_threads.each(&block)
  end

  #
  # Returns an array of thread identifiers.
  #
  def get_threads
    request = Packet.create_request('stdapi_sys_process_thread_get_threads')
    threads = []

    request.add_tlv(TLV_TYPE_PID, process.pid)

    response = process.client.send_request(request)

    response.each(TLV_TYPE_THREAD_ID) { |thr|
      threads << thr.value
    }

    return threads
  end

protected
  attr_accessor :process # :nodoc:

end

end; end; end; end; end; end; end
