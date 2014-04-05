# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_netapi32

  def self.create_dll(dll_path = 'netapi32')
    dll = DLL.new(dll_path, ApiConstants.manager)

    dll.add_function('NetApiBufferFree','DWORD',[
      ["LPVOID","Buffer","in"]
    ])

    dll.add_function('DsGetDcNameA', 'DWORD',[
      ["PWCHAR","ComputerName","in"],
      ["PWCHAR","DomainName","in"],
      ["PBLOB","DomainGuid","in"],
      ["PWCHAR","SiteName","in"],
      ["DWORD","Flags","in"],
      ["PDWORD","DomainControllerInfo","out"]
    ])

    dll.add_function('NetUserDel', 'DWORD',[
      ["PWCHAR","servername","in"],
      ["PWCHAR","username","in"],
    ])

    dll.add_function('NetGetJoinInformation', 'DWORD',[
      ["PWCHAR","lpServer","in"],
      ["PDWORD","lpNameBuffer","out"],
      ["PDWORD","BufferType","out"]
    ])

    dll.add_function('NetServerEnum', 'DWORD',[
      ["PWCHAR","servername","in"],
      ["DWORD","level","in"],
      ["PDWORD","bufptr","out"],
      ["DWORD","prefmaxlen","in"],
      ["PDWORD","entriesread","out"],
      ["PDWORD","totalentries","out"],
      ["DWORD","servertype","in"],
      ["PWCHAR","domain","in"],
      ["DWORD","resume_handle","inout"]
    ])

    dll.add_function('NetWkstaUserEnum', 'DWORD', [
      ["PWCHAR","servername","in"],
      ["DWORD","level","in"],
      ["PDWORD","bufptr","out"],
      ["DWORD","prefmaxlen","in"],
      ["PDWORD","entriesread","out"],
      ["PDWORD","totalentries","out"],
      ["DWORD","resume_handle","inout"]
    ])

    dll.add_function('NetUserGetGroups', 'DWORD', [
      ["PWCHAR","servername","in"],
      ["PWCHAR","username","in"],
      ["DWORD","level","in"],
      ["PDWORD","bufptr","out"],
      ["DWORD","prefmaxlen","in"],
      ["PDWORD","entriesread","out"],
      ["PDWORD","totalentries","out"]
    ])

    return dll
  end

end

end; end; end; end; end; end; end

