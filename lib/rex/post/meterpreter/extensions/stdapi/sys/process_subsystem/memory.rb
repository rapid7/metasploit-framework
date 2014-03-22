# -*- coding: binary -*-

require 'rex/post/meterpreter/client'
require 'rex/post/meterpreter/extensions/stdapi/constants'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Sys
module ProcessSubsystem

###
#
# Provides an interface to allocate, free, read, write, query,
# protect, lock, and unlock memory in the context of a given
# process.
#
###
class Memory

  # Page protection translation hash
  @@page_protection_map =
  {
    PROT_NONE                => PAGE_NOACCESS,
    PROT_EXEC                => PAGE_EXECUTE,
    PROT_EXEC | PROT_READ    => PAGE_EXECUTE_READ,
    PROT_EXEC | PROT_READ |
      PROT_WRITE            => PAGE_EXECUTE_READWRITE,
    PROT_EXEC | PROT_READ |
      PROT_WRITE | PROT_COW => PAGE_EXECUTE_WRITECOPY,
    PROT_READ                => PAGE_READONLY,
    PROT_READ | PROT_WRITE   => PAGE_READWRITE,
    PROT_READ | PROT_WRITE |
      PROT_COW              => PAGE_WRITECOPY,
    PROT_WRITE               => PAGE_READWRITE
  }

  ##
  #
  # Constructor
  #
  ##

  #
  # Initializes a memory modification instance with the supplied process
  # instance.
  #
  def initialize(process)
    self.process = process
  end

  #
  # Allocate storage of the supplied length and returns the
  # address at which the memory was allocated.
  #
  def allocate(length, protection = nil, base = nil)
    allocation_type = MEM_COMMIT

    # If no protection was supplied, default to the most flexible
    if (protection == nil)
      protection = PAGE_EXECUTE_READWRITE
    else
      protection = gen_prot_to_specific(protection)
    end

    # If the preferred base is non-nil, set the reserve flag
    if (base != nil)
      allocation_type |= MEM_RESERVE
    end

    return _allocate(base, length, allocation_type, protection)
  end

  #
  # Low-level memory allocation.
  #
  def _allocate(base, length, allocation_type, protection)
    request = Packet.create_request('stdapi_sys_process_memory_allocate')

    # Populate the request
    if (base != nil)
      request.add_tlv(TLV_TYPE_BASE_ADDRESS, base)
    end

    request.add_tlv(TLV_TYPE_HANDLE, process.handle)
    request.add_tlv(TLV_TYPE_LENGTH, length)
    request.add_tlv(TLV_TYPE_ALLOCATION_TYPE, allocation_type)
    request.add_tlv(TLV_TYPE_PROTECTION, protection)

    # Transmit the request
    response = process.client.send_request(request);

    return response.get_tlv_value(TLV_TYPE_BASE_ADDRESS)
  end

  #
  # Deallocate a region of memory in the context of a process.
  #
  def free(base, length = 0)
    return _free(base, length)
  end

  #
  # Low-level memory deallocation.
  #
  def _free(base, length)
    request = Packet.create_request('stdapi_sys_process_memory_free')

    request.add_tlv(TLV_TYPE_HANDLE, process.handle)
    request.add_tlv(TLV_TYPE_BASE_ADDRESS, base)
    request.add_tlv(TLV_TYPE_LENGTH, length)

    response = process.client.send_request(request)

    return true
  end

  #
  # Read memory from the context of a process and return the buffer.
  #
  def read(base, length)
    request = Packet.create_request('stdapi_sys_process_memory_read')

    request.add_tlv(TLV_TYPE_HANDLE, process.handle)
    request.add_tlv(TLV_TYPE_BASE_ADDRESS, base)
    request.add_tlv(TLV_TYPE_LENGTH, length)

    response = process.client.send_request(request)

    return response.get_tlv_value(TLV_TYPE_PROCESS_MEMORY)
  end

  #
  # Write memory to the context of a process and return the number of bytes
  # actually written.
  #
  def write(base, data)
    request = Packet.create_request('stdapi_sys_process_memory_write')

    request.add_tlv(TLV_TYPE_HANDLE, process.handle)
    request.add_tlv(TLV_TYPE_BASE_ADDRESS, base)
    request.add_tlv(TLV_TYPE_PROCESS_MEMORY, data)

    response = process.client.send_request(request)

    return response.get_tlv_value(TLV_TYPE_LENGTH)
  end

  #
  # Queries an address for information about its state.
  #
  def query(base)
    request = Packet.create_request('stdapi_sys_process_memory_query')

    request.add_tlv(TLV_TYPE_HANDLE, process.handle)
    request.add_tlv(TLV_TYPE_BASE_ADDRESS, base)

    response = process.client.send_request(request)

    # Build out the hash from the response information
    info = {}

    info['BaseAddress']       = response.get_tlv_value(TLV_TYPE_BASE_ADDRESS)
    info['AllocationBase']    = response.get_tlv_value(TLV_TYPE_ALLOC_BASE_ADDRESS)
    info['AllocationProtect'] = specific_prot_to_gen(response.get_tlv_value(TLV_TYPE_ALLOC_PROTECTION))
    info['RegionSize']        = response.get_tlv_value(TLV_TYPE_LENGTH)

    # Translate the memory state
    state = response.get_tlv_value(TLV_TYPE_MEMORY_STATE)

    if (state == MEM_FREE)
      info['Available'] = true
    elsif (state == MEM_COMMIT)
      info['Available'] = false
    elsif (state == MEM_RESERVE)
      info['Reserved'] = true
    end

    # Translate the region protections
    info['Protect'] = specific_prot_to_gen(response.get_tlv_value(TLV_TYPE_PROTECTION))

    # Translate the memory type
    type = response.get_tlv_value(TLV_TYPE_MEMORY_TYPE)

    if (type == MEM_IMAGE)
      info['ImageMapping'] = true
    elsif (type == MEM_MAPPED)
      info['MemoryMapping'] = true
    elsif (type == MEM_PRIVATE)
      info['PrivateMapping'] = true
    end

    return info
  end

  #
  # Change the protection masks on the region supplied in base.
  #
  def protect(base, length = nil, protection = nil)
    request = Packet.create_request('stdapi_sys_process_memory_protect')

    if (length == nil)
      length = 4096
    end

    # If no protection was supplied, default to the most flexible
    if (protection == nil)
      protection = PAGE_EXECUTE_READWRITE
    else
      protection = gen_prot_to_specific(protection)
    end

    request.add_tlv(TLV_TYPE_HANDLE, process.handle)
    request.add_tlv(TLV_TYPE_BASE_ADDRESS, base)
    request.add_tlv(TLV_TYPE_LENGTH, length)
    request.add_tlv(TLV_TYPE_PROTECTION, protection)

    # Send the request
    response = process.client.send_request(request)

    # Return the old protection to the caller
    return specific_prot_to_gen(response.get_tlv_value(TLV_TYPE_PROTECTION))
  end

  #
  # Lock a region of memory into physical memory so that it can't be
  # swapped to disk.  This can only be done in the context of the
  # process that is running the meterpreter server.  The instance's
  # handle is ignored.
  #
  def lock(base, length)
    request = Packet.create_request('stdapi_sys_process_memory_lock')

    request.add_tlv(TLV_TYPE_BASE_ADDRESS, base)
    request.add_tlv(TLV_TYPE_LENGTH, length)

    response = process.client.send_request(request)

    return true
  end

  #
  # Unloock a region of memory into physical memory so that it can be
  # swapped to disk.  This can only be done in the context of the
  # process that is running the meterpreter server.  The instance's
  # handle is ignored.
  #
  def unlock(base, length)
    request = Packet.create_request('stdapi_sys_process_memory_unlock')

    request.add_tlv(TLV_TYPE_BASE_ADDRESS, base)
    request.add_tlv(TLV_TYPE_LENGTH, length)

    response = process.client.send_request(request)

    return true
  end


  ##
  #
  # Conditionals
  #
  ##

  #
  # Check to see if an address is readable.
  #
  def readable?(base)
    info = nil

    begin
      info = query(base)
    rescue
    end

    if ((info != nil) &&
        (info['Available'] == false) &&
        (info['Protect'] & PROT_READ == PROT_READ))
      return true
    end

    return false
  end

  #
  # Check to see if an address is writable.
  #
  def writable?(base)
    info = nil

    begin
      info = query(base)
    rescue
    end

    if ((info != nil) &&
        (info['Available'] == false) &&
        (info['Protect'] & PROT_WRITE == PROT_WRITE))
      return true
    end

    return false
  end

protected

  #
  # Translates general protection flags to specific protection flags.
  #
  def gen_prot_to_specific(prot)
    if (prot == nil)
      return PAGE_READ
    end

    return @@page_protection_map[prot]
  end

  #
  # Translates specific protection flags to general protection flags.
  #
  def specific_prot_to_gen(prot)

    if (prot == nil)
      return PAGE_READONLY
    end

    return @@page_protection_map.invert[prot]
  end

  attr_accessor :process # :nodoc:
end

end; end; end; end; end; end; end
