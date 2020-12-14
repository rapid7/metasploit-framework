##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Shodan Host Port',
      'Description' => %q{
        This module uses the shodan API to return all port information found on a given host IP.
      },
      'Author' =>
        [ 'natto97' ],
      'License' => MSF_LICENSE,
      'References' =>
        [
          [ 'URL', 'https://honeyscore.shodan.io/']
        ]
      )
    )
    register_options(
      [
        OptString.new('SHODAN_APIKEY', [true, 'The SHODAN API key'])
      ])
  end
  def run
    # check our API key is somewhat sane
    unless /^[a-z\d]{32}$/i.match?(datastore['SHODAN_APIKEY'])
      fail_with(Failure::BadConfig, 'Shodan API key should be 32 characters a-z,A-Z,0-9.')
    end
    key = datastore['SHODAN_APIKEY']
    # Check the length of the key (should be 32 chars)
    if key.length != 32
      print_error('Invalid API key (Not long enough)')
      return
    end
    cli = Rex::Proto::Http::Client.new('api.shodan.io', 443, {}, true)
    cli.connect
    req = cli.request_cgi({
      'uri'    => "/shodan/host/#{rhost}?key=#{key}&minify=true",
      'method' => 'GET',
      })
    res = cli.send_recv(req)
    cli.close
    if res.nil?
      fail_with(Failure::Unknown, 'Unable to connect to shodan')
    end
    if res.code != 200
      print_error('Shodan did not respond in an expected way. Check your api key')
    end
    json = res.get_json_document
    if json["ports"] != nil
      json["ports"].each do |post|
        print_good("#{rhost}:#{post}")
      end
    end
  end
end
