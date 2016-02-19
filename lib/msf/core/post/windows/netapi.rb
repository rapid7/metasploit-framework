# -*- coding: binary -*-
module Msf
class Post
module Windows

module NetAPI

  MAX_PREFERRED_LENGTH = -1
  SV_TYPE_ALL = 0xFFFFFFFF
  SV_TYPE_DOMAIN_ENUM = 0x80000000
  SV_TYPE_DOMAIN_BAKCTRL = 0x00000010
  SV_TYPE_DOMAIN_CTRL = 0x00000008

  ERROR_ACCESS_DENIED = 5
  ERROR_NOT_ENOUGH_MEMORY = 8
  ERROR_INVALID_PARAMETER = 87
  ERROR_INVALID_LEVEL = 124
  ERROR_MORE_DATA = 234
  ERROR_NO_BROWSER_SERVERS_FOUND = 6118

  NERR_ClientNameNotFound = 2312
  NERR_InvalidComputer = 2351
  NERR_UserNotFound = 2221

  def UnicodeByteStringToAscii(str)
    length = (str.index "\0\0\0") + 1
    Rex::Text.to_ascii(str[0..length])
  end

  def netapi_buffer_free(ptr)
    # Free the buffer
    ret = client.railgun.netapi32.NetApiBufferFree(ptr)
    vprint_error("Unable to free buffer, Error Code: #{ret['return']}") unless ret['return'] == 0
  end

  def net_server_enum(server_type=SV_TYPE_ALL, domain=nil)
    hosts = []

    result = client.railgun.netapi32.NetServerEnum(
        nil,    # servername
        100,    # level (100/101)
        4,      # bufptr
        MAX_PREFERRED_LENGTH, # prefmaxlen
        4,      # entries read
        4,      # total entries
        server_type, # server_type
        domain,    # domain
        nil     # resume handle
    )

    case result['return']
    when 0
      # Railgun assumes PDWORDS are pointers and returns 8 bytes for x64 architectures.
      # Therefore we need to truncate the result value to an actual
      # DWORD for entriesread or totalentries.
      hosts = read_server_structs(result['bufptr'], (result['entriesread'] % 4294967296), domain, server_type)
    when ERROR_NO_BROWSER_SERVERS_FOUND
      print_error("ERROR_NO_BROWSER_SERVERS_FOUND")
      return nil
    when ERROR_MORE_DATA
      vprint_error("ERROR_MORE_DATA")
      return nil
    end

    netapi_buffer_free(result['bufptr'])

    return hosts
  end

  def read_server_structs(start_ptr, count, domain, server_type)
    hosts = []
    return hosts if count <= 0

    ptr_size = client.railgun.util.pointer_size
    ptr = (ptr_size == 8) ? 'Q<' : 'V'

    base = 0
    # Struct -> Ptr, Ptr
    struct_size = ptr_size * 2

    mem = client.railgun.memread(start_ptr, struct_size*count)

    count.times do
      x = {}
      x[:version]= mem[(base + 0),ptr_size].unpack(ptr).first
      nameptr = mem[(base + ptr_size),ptr_size].unpack(ptr).first
      x[:name] = UnicodeByteStringToAscii(client.railgun.memread(nameptr, 255))
      hosts << x
      base += struct_size
    end

    hosts
  end

  def net_session_enum(hostname, username)
    sessions = []

    result = client.railgun.netapi32.NetSessionEnum(
        hostname,   # servername
        nil,        # UncClientName
        username,   # username
        10,         # level
        4,          # bufptr
        MAX_PREFERRED_LENGTH, # prefmaxlen
        4,          # entriesread
        4,          # totalentries
        nil         # resume_handle
    )

    case result['return']
    when 0
      vprint_error("#{hostname} Session identified")
      sessions = read_session_structs(result['bufptr'], (result['entriesread'] % 4294967296), hostname)
    when ERROR_ACCESS_DENIED
      vprint_error("#{hostname} Access denied...")
      return nil
    when 53
      vprint_error("Host not found or did not respond: #{hostname}")
      return nil
    when 123
      vprint_error("Invalid host: #{hostname}")
      return nil
    when NERR_UserNotFound
      return nil
    when ERROR_MORE_DATA
      vprint_error("#{hostname} ERROR_MORE_DATA")
    else
      vprint_error("Unaccounted for error code: #{result['return']}")
      return nil
    end

    netapi_buffer_free(result['bufptr'])

    return sessions
  end

  def read_session_structs(start_ptr, count, hostname)
    sessions = []
    return sessions if count <= 0

    ptr_size = client.railgun.util.pointer_size
    ptr = (ptr_size == 8) ? 'Q<' : 'V'

    base = 0
    # Struct -> Ptr, Ptr, Dword Dword
    struct_size = (ptr_size * 2) + 8
    mem = client.railgun.memread(start_ptr, struct_size*count)

    count.times do
      sess = {}
      cnameptr = mem[(base + 0),ptr_size].unpack(ptr).first
      usernameptr = mem[(base + ptr_size),ptr_size].unpack(ptr).first
      sess[:usetime] = mem[(base + (ptr_size * 2)),4].unpack('V').first
      sess[:idletime] = mem[(base + (ptr_size * 2) + 4),4].unpack('V').first
      sess[:cname] = UnicodeByteStringToAscii(client.railgun.memread(cnameptr,255))
      sess[:username] = UnicodeByteStringToAscii(client.railgun.memread(usernameptr,255))
      sess[:hostname] = hostname
      sessions << sess
      base = base + struct_size
    end

    sessions
  end

end # NetAPI
end # Windows
end # Post
end # Msf
