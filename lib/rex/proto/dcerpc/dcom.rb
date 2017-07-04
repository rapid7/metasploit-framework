# -*- coding: binary -*-
module Rex
module Proto
module DCERPC
class Dcom

require 'rex/text'
  
  def self.parse(data)
    orpcthat_flags,
    orpcthat_extent_array,
    oxid,
    pad,
    unknown,
    pad1,
    unknown = data.unpack('VVa8vvvv')

    string_bindings, security_bindings, e = parse_dualstringarray(data[24..-1])
    data = data[e+30..-1]


    ipid,
    auth_hint,
    version_major,
    version_minor,
    hresult = data.unpack('a16VvvV')
    ipid = Rex::Proto::DCERPC::UUID.uuid_unpack(ipid)

    interface_data = data[36..-1]
    #puts interface_data.inspect
    cntdata,
    cntdata,
    objref_meow,
    objref_flags,
    objref_iid,
    # StdObjRef
    stdobjref_flags,
    stdobjref_publicrefs,
    stdobjref_oxid,
    stdobjref_oid,
    stdobjref_ipid = interface_data.unpack('VVa4Va16VVa8a8a16')

    objref_iid = Rex::Proto::DCERPC::UUID.uuid_unpack(objref_iid)
    stdobjref_ipid = Rex::Proto::DCERPC::UUID.uuid_unpack(stdobjref_ipid)

    istring_bindings, isecurity_bindings, ie = parse_dualstringarray(interface_data[72..-1])
    hresult_data = interface_data[ie+82..-1]

    port = nil
    for towerid, netaddr in string_bindings
      if towerid == 7
        port = /\[(\d+)\]/.match(netaddr)[1]
        break
      end
    end

    return objref_iid, port, stdobjref_ipid
  end

  def self.parse_dualstringarray(data)
    num_entries,
                security_offset = data.unpack('vv')

                offset = 4

                string_binding_end = offset + security_offset*2
                security_offset_end = offset + num_entries*2
                string_binding = data[offset..string_binding_end]
                $stdout.puts("#{string_binding}")
                security_binding = data[string_binding_end..security_offset_end]

                string_bindings = []
                while string_binding.length > 0
                        towerid = string_binding.unpack('v').first
                        if towerid == 0
                                break
                        end
                        e = string_binding.index("\x00\x00") || -2
                        sb = Rex::Text.to_ascii(string_binding[2..e])
                        string_bindings << [towerid, sb]
                        string_binding = string_binding[e+3..-1]

                end

                security_bindings = []
                while security_binding.length > 0
                        authn_svc, reserved = security_binding.unpack('vv')
                        if authn_svc == 0
                                break
                        end
                        e = security_binding.index("\x00\x00") || -1
                        so = Rex::Text.to_ascii(security_binding[4..e])
                        security_bindings << [authn_svc, so]
                        security_binding = security_binding[e+3..-1]
                end
    
    return string_bindings, security_bindings, num_entries*2
  end

  #
  # http://msdn.microsoft.com/en-us/library/cc226801.aspx
  #
 	
  def create_stub_header(uuid='61eb59f1-1efb-11d1-bcd9-00609792d26c',ext='',flags=0)
    binuuid = Rex::Text.hex_to_raw(UUID.uuid_pack(uuid)) # ORPCTHIS
    # ext  ||= Rex::Text.hex_to_raw('605e0d00') # Extensions

    hdr = [
      5,     # Version High
      1,     # Version Low
      flags, # Flags
      0,     # Reserved
    ].pack('vvVV') << binuuid << ext

    return hdr
  end

end
end
end
end
