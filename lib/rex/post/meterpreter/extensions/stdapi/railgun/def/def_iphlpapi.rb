# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_iphlpapi

  def self.create_dll(dll_path = 'iphlpapi')
    dll = DLL.new(dll_path, ApiConstants.manager)

    dll.add_function('CancelIPChangeNotify', 'BOOL',[
      ["PBLOB","notifyOverlapped","in"],
      ])

    dll.add_function('CreateProxyArpEntry', 'DWORD',[
      ["DWORD","dwAddress","in"],
      ["DWORD","dwMask","in"],
      ["DWORD","dwIfIndex","in"],
      ])

    dll.add_function('DeleteIPAddress', 'DWORD',[
      ["DWORD","NTEContext","in"],
      ])

    dll.add_function('DeleteProxyArpEntry', 'DWORD',[
      ["DWORD","dwAddress","in"],
      ["DWORD","dwMask","in"],
      ["DWORD","dwIfIndex","in"],
      ])

    dll.add_function('FlushIpNetTable', 'DWORD',[
      ["DWORD","dwIfIndex","in"],
      ])

    dll.add_function('GetAdapterIndex', 'DWORD',[
      ["PWCHAR","AdapterName","in"],
      ["PDWORD","IfIndex","inout"],
      ])

    dll.add_function('GetBestInterface', 'DWORD',[
      ["DWORD","dwDestAddr","in"],
      ["PDWORD","pdwBestIfIndex","inout"],
      ])

    dll.add_function('GetBestInterfaceEx', 'DWORD',[
      ["PBLOB","pDestAddr","in"],
      ["PDWORD","pdwBestIfIndex","inout"],
      ])

    dll.add_function('GetFriendlyIfIndex', 'DWORD',[
      ["DWORD","IfIndex","in"],
      ])

    dll.add_function('GetNumberOfInterfaces', 'DWORD',[
      ["PDWORD","pdwNumIf","inout"],
      ])

    dll.add_function('GetRTTAndHopCount', 'BOOL',[
      ["DWORD","DestIpAddress","in"],
      ["PDWORD","HopCount","inout"],
      ["DWORD","MaxHops","in"],
      ["PDWORD","RTT","inout"],
      ])

    dll.add_function('NotifyAddrChange', 'DWORD',[
      ["PDWORD","Handle","inout"],
      ["PBLOB","overlapped","in"],
      ])

    dll.add_function('NotifyRouteChange', 'DWORD',[
      ["PDWORD","Handle","inout"],
      ["PBLOB","overlapped","in"],
      ])

    dll.add_function('SendARP', 'DWORD',[
      ["DWORD","DestIP","in"],
      ["DWORD","SrcIP","in"],
      ["PBLOB","pMacAddr","out"],
      ["PDWORD","PhyAddrLen","inout"],
      ])

    dll.add_function('SetIpTTL', 'DWORD',[
      ["DWORD","nTTL","in"],
      ])

    return dll
  end

end

end; end; end; end; end; end; end


