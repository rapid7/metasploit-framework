#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/post/thread'
require 'rex/post/meterpreter/client'
require 'rex/post/meterpreter/extensions/stdapi/constants'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Sys

##
#
# This class implements the Rex::Post::Thread interface which
# wrappers a logical thread for a given process.
#
##
class Thread < Rex::Post::Thread

  include Rex::Post::Meterpreter::ObjectAliasesContainer

  ##
  #
  # Constructor
  #
  ##

  #
  # Initialize the thread instance.
  #
  def initialize(process, handle, tid)
    self.process = process
    self.handle  = handle
    self.tid     = tid
    ObjectSpace.define_finalizer( self, self.class.finalize(self.process.client, self.handle) )
  end

  def self.finalize(client,handle)
    proc { self.close(client,handle) }
  end

  ##
  #
  # Execution
  #
  ##

  #
  # Suspends the thread's execution.
  #
  def suspend
    request = Packet.create_request('stdapi_sys_process_thread_suspend')

    request.add_tlv(TLV_TYPE_THREAD_HANDLE, handle)

    process.client.send_request(request)

    return true
  end

  #
  # Resumes the thread's execution.
  #
  def resume
    request = Packet.create_request('stdapi_sys_process_thread_resume')

    request.add_tlv(TLV_TYPE_THREAD_HANDLE, handle)

    process.client.send_request(request)

    return true
  end

  #
  # Terminates the thread's execution.
  #
  def terminate(code)
    request = Packet.create_request('stdapi_sys_process_thread_terminate')

    request.add_tlv(TLV_TYPE_THREAD_HANDLE, handle)
    request.add_tlv(TLV_TYPE_EXIT_CODE, code)

    process.client.send_request(request)

    return true
  end

  ##
  #
  # Register manipulation
  #
  ##

  #
  # Queries the register state of the thread.
  #
  def query_regs
    request = Packet.create_request('stdapi_sys_process_thread_query_regs')
    regs    = {}

    request.add_tlv(TLV_TYPE_THREAD_HANDLE, handle)

    response = process.client.send_request(request)

    response.each(TLV_TYPE_REGISTER) { |reg|
      regs[reg.get_tlv_value(TLV_TYPE_REGISTER_NAME)] = reg.get_tlv_value(TLV_TYPE_REGISTER_VALUE_32)
    }

    return regs
  end

  #
  # Sets the register state of the thread.  The registers are supplied
  # in the form of a hash.
  #
  def set_regs(regs_hash)
    request = Packet.create_request('stdapi_sys_process_thread_set_regs')

    request.add_tlv(TLV_TYPE_THREAD_HANDLE, handle)

    # Add all of the register that we're setting
    regs_hash.each_key { |name|
      t = request.add_tlv(TLV_TYPE_REGISTER)

      t.add_tlv(TLV_TYPE_REGISTER_NAME, name)
      t.add_tlv(TLV_TYPE_REGISTER_VALUE_32, regs_hash[name])
    }

    process.client.send_request(request)

    return true
  end

  #
  # Formats the registers in a pretty way.
  #
  def pretty_regs
    regs = query_regs

    buf  = sprintf("eax=%.8x ebx=%.8x ecx=%.8x edx=%.8x esi=%.8x edi=%.8x\n",
                   regs['eax'], regs['ebx'], regs['ecx'], regs['edx'], regs['esi'], regs['edi'])
    buf += sprintf("eip=%.8x esp=%.8x ebp=%.8x\n",
                   regs['eip'], regs['esp'], regs['ebp'])
    buf += sprintf("cs=%.4x ss=%.4x ds=%.4x es=%.4x fs=%.4x gs=%.4x\n",
                   regs['cs'], regs['ss'], regs['ds'], regs['es'], regs['fs'], regs['gs'])

    return buf
  end

  ##
  #
  # Closure
  #
  ##

  #
  # Closes the thread handle.
  #
  def self.close(client, handle)
    request = Packet.create_request('stdapi_sys_process_thread_close')
    request.add_tlv(TLV_TYPE_THREAD_HANDLE, handle)
    client.send_request(request, nil)
    handle = nil
    return true
  end

  # Instance method
  def close
    self.class.close(self.process.client, self.handle)
  end

  attr_reader :process, :handle, :tid # :nodoc:
protected
  attr_writer :process, :handle, :tid # :nodoc:

end

end; end; end; end; end; end
