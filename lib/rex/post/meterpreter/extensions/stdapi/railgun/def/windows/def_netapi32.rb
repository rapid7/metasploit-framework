# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_windows_netapi32

  def self.create_library(constant_manager, library_path = 'netapi32')
    dll = Library.new(library_path, constant_manager)

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

    dll.add_function('NetSessionEnum', 'DWORD',[
        ['PWCHAR','servername','in'],
        ['PWCHAR','UncClientName','in'],
        ['PWCHAR','username','in'],
        ['DWORD','level','in'],
        ['PDWORD','bufptr','out'],
        ['DWORD','prefmaxlen','in'],
        ['PDWORD','entriesread','out'],
        ['PDWORD','totalentries','out'],
        ['PDWORD','resume_handle','inout']
    ])

    dll.add_function('NetApiBufferFree', 'DWORD', [
        ['LPVOID','buffer','in']
    ])

    dll.add_function('NetUserChangePassword', 'DWORD', [
      ["PWCHAR","domainname","in"],
      ["PWCHAR","username","in"],
      ["PWCHAR","oldpassword","in"],
      ["PWCHAR","newpassword","in"]
    ])

    return dll
  end

end

end; end; end; end; end; end; end

