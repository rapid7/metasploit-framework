##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Shodan Host Port',
        'Description' => %q{
          This module uses the shodan API to return all port information found on a given host IP.
        },
        'Author' => [ 'natto97' ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'https://honeyscore.shodan.io/']
        ]
      )
    )
    register_options(
      [
        OptString.new('SHODAN_APIKEY', [true, 'The SHODAN API key'])
      ]
    )
    deregister_options('SSL')
    deregister_options('RPORT')
    deregister_options('VHOST')
  end

  def run
    # check our API key is somewhat sane
    unless /^[a-z\d]{32}$/i.match?(datastore['SHODAN_APIKEY'])
      fail_with(Failure::BadConfig, 'Shodan API key should be 32 characters a-z,A-Z,0-9.')
    end
    key = datastore['SHODAN_APIKEY']
    # Check the length of the key (should be 32 chars)
    if key.length != 32
      fail_with(Failure::BadConfig, 'Invalid API key (Not long enough)')
    end
    cli = Rex::Proto::Http::Client.new('api.shodan.io', 443, {}, true)
    cli.connect
    req = cli.request_cgi({
      'uri' => "/shodan/host/#{rhost}?key=#{key}&minify=true",
      'method' => 'GET'
    })
    res = cli.send_recv(req)
    cli.close
    if res.nil?
      fail_with(Failure::Unreachable, 'Unable to connect to shodan')
    end
    if res.body =~ /No information available for that IP/
      print_error('The target IP address has not been scanned by Shodan!')
      return
    end
    if res.code != 200
      fail_with(Failure::UnexpectedReply, 'Shodan did not respond in an expected way. Check your api key')
    end
    json = res.get_json_document
    if !json.nil? && !json['ports'].nil? && !json['ports'].empty?
      json['ports'].each do |post|
        print_good("#{rhost}:#{post}")
        report_service(host: rhost, port: post, name: 'shodan')
      end
    else
      print_error("Shodan did not return any open ports for #{rhost}!")
    end
  end
end
