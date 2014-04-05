##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Udp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Citrix MetaFrame ICA Published Applications Scanner',
      'Description'    => %q{
        This module attempts to query Citrix Metaframe ICA server to obtain
        a published list of applications.
      },
      'Author'         => [ 'patrick' ],
      'References'     =>
        [
          [ 'URL', 'http://www.securiteam.com/exploits/5CP0B1F80S.html' ],
        ]
    ))

    register_options(
      [
        Opt::RPORT(1604),
      ], self.class)
  end

  def autofilter
    false
  end

  def run
    connect_udp

    print_status("Attempting to contact Citrix ICA service...")

    client_connect =
      "\x20\x00\x01\x30\x02\xfd\xa8\xe3\x00\x00\x00\x00\x00\x00\x00\x00" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    # Server hello response
    server_response =
      "\x30\x00\x02\x31\x02\xfd\xa8\xe3\x02\x00\x06\x44"

    udp_sock.put(client_connect)
    res = udp_sock.get(3)

    if (res[0,server_response.length] == server_response)
      print_status("Citrix MetaFrame ICA server detected. Requesting Published Applications list...")

      find_published =
        "\x2a\x00\x01\x32\x02\xfd\xa8\xe3\x00\x00\x00\x00\x00\x00\x00\x00" +
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x21\x00\x02\x00" +
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      server_list_pre =
        "\xea\x00\x04\x33\x02\xfd\xa8\xe3\x02\x00\x06\x44\xac\x1f\x03\x1f" +
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00" +
        "\x0b\x00\x28\x00\x00\x00\x00\x00"

      udp_sock.put(find_published)
      res = udp_sock.get(3)

      if (res.index(server_list_pre) == 0) # good packet, with following data
        print_status("Citrix Applications Reported:\r\n" + res[server_list_pre.length,res.length].gsub("\x00","\r\n"))
      end
    else
      print_error("Citrix did not report any Published Applications. Try the brute force module instead.")
    end

    disconnect_udp
  end

end
