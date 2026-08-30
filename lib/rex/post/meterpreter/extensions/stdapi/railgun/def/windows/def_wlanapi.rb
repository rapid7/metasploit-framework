# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_windows_wlanapi

  def self.create_library(constant_manager, library_path = 'wlanapi')
    dll = Library.new(library_path, constant_manager)


    dll.add_function( 'WlanOpenHandle', 'DWORD',[
        ['DWORD', 'dwClientVersion', 'in'],
        ['LPVOID', 'pReserved', 'in'],
        ['PDWORD', 'pdwNegotiatedVersion', 'out'],
        ['PDWORD', 'phClientHandle', 'out']])

    dll.add_function( 'WlanEnumInterfaces', 'DWORD',[
        ['DWORD', 'hClientHandle', 'in'],
        ['LPVOID', 'pReserved', 'in'],
        ['PDWORD', 'ppInterfaceList', 'out']])

    dll.add_function( 'WlanGetProfileList', 'DWORD',[
        ['DWORD', 'hClientHandle', 'in'],
        ['PBLOB', 'pInterfaceGuid', 'in'],
        ['LPVOID', 'pReserved', 'in'],
        ['PDWORD', 'ppProfileList', 'out']])

    dll.add_function( 'WlanGetProfile', 'DWORD',[
        ['DWORD', 'hClientHandle', 'in'],
        ['PBLOB', 'pInterfaceGuid', 'in'],
        ['PBLOB', 'strProfileName', 'in'],
        ['LPVOID', 'pReserved', 'in'],
        ['PDWORD', 'pstrProfileXML', 'out'],
        ['PDWORD', 'pdwFlags', 'inout'],
        ['PDWORD', 'pdwGrantedAccess', 'out']])

    dll.add_function( 'WlanFreeMemory', 'DWORD',[
        ['LPVOID', 'pMemory', 'in']])

    dll.add_function( 'WlanCloseHandle', 'DWORD',[
        ['DWORD', 'hClientHandle', 'in'],
        ['LPVOID', 'pReserved', 'in']])

    dll.add_function( 'WlanQueryInterface', 'DWORD',[
        ['DWORD', 'hClientHandle', 'in'],
        ['PBLOB', 'pInterfaceGuid', 'in'],
        ['DWORD', 'OpCode', 'in'],
        ['LPVOID', 'pReserved', 'in'],
        ['PDWORD', 'pdwDataSize', 'out'],
        ['PDWORD', 'ppData', 'out'],
        ['PDWORD', 'pWlanOpcodeValueType', 'out']])

    dll.add_function( 'WlanScan', 'DWORD',[
        ['DWORD', 'hClientHandle', 'in'],
        ['PBLOB', 'pInterfaceGuid', 'in'],
        ['PBLOB', 'pDot11Ssid', 'in'],
        ['PBLOB', 'pIeData', 'in'],
        ['LPVOID', 'pReserved', 'in']])

    dll.add_function( 'WlanGetNetworkBssList', 'DWORD',[
        ['DWORD', 'hClientHandle', 'in'],
        ['PBLOB', 'pInterfaceGuid', 'in'],
        ['PBLOB', 'pDot11Ssid', 'in'],
        ['DWORD', 'dot11BssType', 'in'],
        ['BOOL', 'bSecurityEnabled', 'in'],
        ['LPVOID', 'pReserved', 'in'],
        ['PDWORD', 'ppWlanBssList', 'out']])

    dll.add_function( 'WlanDisconnect', 'DWORD',[
        ['DWORD', 'hClientHandle', 'in'],
        ['PBLOB', 'pInterfaceGuid', 'in'],
        ['LPVOID', 'pReserved', 'in']])


    return dll
  end

end

end; end; end; end; end; end; end


