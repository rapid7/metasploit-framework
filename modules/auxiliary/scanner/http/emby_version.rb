##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/btnz-k/msf_emby
# Exploit Title: Emby Version Checker
# Date: 2020.11.17
# Exploit Author: Btnz
# Vendor Homepage: https://emby.media/
# Software Link: https://emby.media/download.html
# Version: Prior to 4.5
# Tested on: Ubuntu, Windows
# CVE: CVE-2020-26948
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'Emby Version Checker',
      'Description' => '
            This module attempts to identify the version of an Emby Media Server running on
            a host. If you wish to see all the information available, set VERBOSE to true. Based on the vulnerability CVE-2020-26948.
          ',
      'Author' => 'Btnz',
      'Version' => '1.0.2020.10.09.01',
      'License' => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(8096),
        OptString.new('BASEPATH', [true, 'The base path, usually just /', '/']),
        OptInt.new('TIMEOUT', [true, 'Timeout for the version checker', 30])
      ]
    )
    deregister_options('VHOST', 'FILTER', 'INTERFACE', 'PCAPFILE', 'SNAPLEN', 'SSL')
  end

  def to
    return 30 if datastore['TIMEOUT'].to_i.zero?

    datastore['TIMEOUT'].to_i
  end

  def run_host(ip)
    res = send_request_cgi({
      'uri' => "#{datastore['BASEPATH']}System/Info/Public",
      'method' => 'GET'
    })
    if res.nil? || res.code != 200
      vprint_error('[Emby Version] failed to connect')
      return
    end

    result = res.get_json_document
    print_status("Identifying Media Server Version on #{peer}")
    print_good("[Media Server] URI: http://#{ip}:#{rport}#{datastore['BASEPATH']}")
    print_good("[Media Server] Version: #{result['Version']}")
    print_good("[Media Server] Internal IP: #{result['LocalAddress']}")
    report_service(host: rhost, port: rport, name: 'emby', info: "Emby Server v.#{result['Version']} (LAN:#{result['LocalAddress']})")
    print_status "All info: #{result}" if datastore['VERBOSE']
    report_note(
      host: ip,
      port: rport,
      proto: 'tcp',
      ntype: 'server_version',
      data: result['Version'],
      info: "Media Server v.#{result['Version']}"
    )
    print_status('Saving host information.')
    report_host(
      host: ip,
      info: "Emby Server v.#{result['Version']} (LAN:#{result['LocalAddress']})"
    )
    end
end
