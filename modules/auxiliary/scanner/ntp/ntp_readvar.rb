##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary


  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner


  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'NTP Clock Variables Disclosure',
      'Description'    => %q{
          This module reads the system internal NTP variables. These variables contain
        potentially sensitive information, such as the NTP software version, operating
        system version, peers, and more.
      },
      'Author'         => [ 'Ewerson Guimaraes(Crash) <crash[at]dclabs.com.br>' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL','http://www.rapid7.com/vulndb/lookup/ntp-clock-variables-disclosure' ],
        ]
      )
    )
    register_options(
    [
      Opt::RPORT(123)
    ], self.class)
  end

  def run_host(ip)

    connect_udp

    readvar = "\x16\x02\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00" #readvar command
    print_status("Connecting target #{rhost}:#{rport}...")

    print_status("Sending command")
    udp_sock.put(readvar)
    reply = udp_sock.recvfrom(65535, 0.1)
    if not reply or reply[0].empty?
      print_error("#{rhost}:#{rport} - Couldn't read NTP variables")
      return
    end
    p_reply = reply[0].split(",")
    arr_count = 0
    while ( arr_count < p_reply.size)
      if arr_count == 0
        print_good("#{rhost}:#{rport} - #{p_reply[arr_count].slice(12,p_reply[arr_count].size)}") #12 is the adjustment of packet garbage
        arr_count =  arr_count + 1
      else
        print_good("#{rhost}:#{rport} - #{p_reply[arr_count].strip}")
        arr_count =  arr_count + 1
      end
    end
    disconnect_udp

  end

end
